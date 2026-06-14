/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
/*
 * SPDX-FileCopyrightText: 2026 Deutsche Telekom Technik GmbH
 * SPDX-FileCopyrightText: 2026 Felix Schneider
 */
package io.camunda.zeebe.engine.processing.bpmn.behavior;

import io.camunda.zeebe.engine.processing.bpmn.BpmnElementContext;
import io.camunda.zeebe.engine.processing.common.Failure;
import io.camunda.zeebe.engine.state.mutable.MutableElementInstanceState;
import io.camunda.zeebe.protocol.record.value.BpmnElementType;
import io.camunda.zeebe.protocol.record.value.ErrorType;
import io.camunda.zeebe.util.Either;
import io.camunda.zeebe.util.buffer.BufferUtil;
import java.util.Map;

/**
 * Detects unintended tight loops in a BPMN process by counting how many times each element is
 * activated within a single process instance.
 *
 * <p>When the activation count for a given element exceeds the configured threshold a {@link
 * Failure} with {@link ErrorType#CONDITION_ERROR} is returned, which will cause an incident to be
 * raised and halt the loop.
 *
 * <p>A {@link Failure} is raised on the very first activation that exceeds the threshold and then
 * again every {@code retryCooldown} activations after that, giving operators a window to resolve
 * the incident without immediately hitting a new one.
 *
 * <h3>Per-element-type configuration</h3>
 *
 * <p>The effective threshold is resolved per {@link BpmnElementType}: a configured per-type
 * override takes precedence over the global default. A per-type value of {@code 0} disables loop
 * detection for that element type entirely. The element type used for resolution is the type of the
 * activated element (for the multi-instance batch check that is the {@code MULTI_INSTANCE_BODY}).
 *
 * <h3>Multi-instance handling — counting outer iterations, not collection items</h3>
 *
 * <p>For a multi-instance element the {@code MULTI_INSTANCE_BODY} wrapper and all of its inner
 * child instances share the same {@code elementId}. The children are activated in a single batch
 * whose size equals the input collection. Counting the children would cause <em>false-positive
 * incidents</em> whenever the collection is larger than {@code maxActivations}, even for processes
 * that have no loop at all.
 *
 * <p>Multi-instance element handling is done entirely at the call site ({@code
 * BpmnStreamProcessor.shouldCheckLoopDetection}), which decides whether to invoke this method based
 * on the MI type (sequential vs parallel) and whether the element is the body or a child. See that
 * method's Javadoc for the complete decision matrix.
 *
 * <h3>Large-collection parallel MI loops</h3>
 *
 * <p>Body-only counting avoids false positives but is slow to detect tight loops where the input
 * collection is large. With {@code maxActivations = 200} and a 100-item collection, the body
 * counter only reaches the threshold after 200 outer iterations by which time 19 900 child
 * activations have already been batch-processed.
 *
 * <p>To detect such scenarios earlier, {@link #checkBatchActivationThreshold} must be called
 * immediately before the parallel child batch is spawned (inside {@code
 * MultiInstanceBodyProcessor.onActivate}, for parallel MI only). It reads the body activation count
 * that was just incremented by {@link #checkActivationThreshold} and checks whether {@code
 * bodyCount × batchSize > maxActivations}. The guard {@code bodyCount ≥ 2} ensures the check is
 * skipped on the very first run so that legitimate large-collection single-run processes are never
 * flagged as loops.
 *
 * <p>The persistent counter is always incremented so the count survives broker restarts and
 * log-entry snapshots.
 */
public final class BpmnLoopDetectionBehavior {

  private static final String CONDITION_ERROR_ACTIVATION_COUNT_EXCEEDED =
      "Expected to activate element '%s' in process instance '%d', but the element has already"
          + " been activated %d times, exceeding the maximum activation threshold of %d.";

  private static final String CONDITION_ERROR_BATCH_ACTIVATION_COUNT_EXCEEDED =
      "Expected to activate element '%s' in process instance '%d', but the parallel"
          + " multi-instance body has been activated %d time(s) with a collection of %d item(s),"
          + " resulting in a projected total of %d child activations which exceeds the maximum"
          + " activation threshold of %d.";

  private final MutableElementInstanceState elementInstanceState;
  private final int maxActivations;
  private final Map<BpmnElementType, Integer> maxActivationsByType;
  private final int retryCooldown;

  public BpmnLoopDetectionBehavior(
      final MutableElementInstanceState elementInstanceState,
      final int maxActivations,
      final Map<BpmnElementType, Integer> maxActivationsByType,
      final int retryCooldown) {
    this.elementInstanceState = elementInstanceState;
    this.maxActivations = maxActivations;
    this.maxActivationsByType = Map.copyOf(maxActivationsByType);
    this.retryCooldown = retryCooldown;
  }

  /**
   * Checks whether the activation count for the element has exceeded the configured threshold.
   *
   * <p>The counter is incremented exactly once, by {@code
   * ProcessInstanceElementActivatingV4Applier} when the {@code ELEMENT_ACTIVATING} event is
   * applied. Because that event is written (and applied) by {@code transitionToActivating} before
   * this check runs, the counter already reflects the current activation when this method reads it.
   * Keeping the increment in the applier ensures the count is correct on event replay (the applier
   * is the single source of truth).
   *
   * <p>This method is a pure threshold check — it has no knowledge of multi-instance elements. The
   * caller ({@code BpmnStreamProcessor.shouldCheckLoopDetection}) is responsible for deciding
   * whether to invoke this method at all, excluding sequential MI bodies and parallel MI children
   * as appropriate.
   *
   * <p>The effective threshold is resolved per {@link BpmnElementType}: a per-type override takes
   * precedence over the global default, and a configured value of {@code 0} disables loop detection
   * for that type. An incident is raised on the <em>first</em> activation that exceeds the
   * effective threshold and then again every {@code retryCooldown} activations after that.
   *
   * @param context the context of the element that is being activated
   * @return {@code Either.right(null)} when within the allowed bounds, or {@code Either.left} with
   *     a {@link Failure} when the threshold is exceeded
   */
  public Either<Failure, Void> checkActivationThreshold(final BpmnElementContext context) {
    final int max = resolveMaxActivations(context.getBpmnElementType());
    if (max <= 0) {
      // Loop detection is disabled for this element type.
      return Either.right(null);
    }

    // The counter was already incremented by ProcessInstanceElementActivatingV4Applier when the
    // ELEMENT_ACTIVATING event was applied (during transitionToActivating, before this check runs),
    // so it already reflects the current activation.
    final long activationCount =
        elementInstanceState.getElementActivationCount(
            context.getProcessInstanceKey(), context.getElementId());

    if (activationCount <= max) {
      return Either.right(null);
    }
    // Always fire on the first activation beyond the threshold (activationCount == max + 1) so the
    // incident is never skipped. After that, throttle re-raising to every retryCooldown activations
    // beyond the threshold.
    final int cooldown = Math.max(1, retryCooldown);
    if (activationCount != max + 1 && (activationCount - max) % cooldown != 0) {
      return Either.right(null);
    }

    final String elementId = BufferUtil.bufferAsString(context.getElementId());
    final String message =
        CONDITION_ERROR_ACTIVATION_COUNT_EXCEEDED.formatted(
            elementId, context.getProcessInstanceKey(), activationCount, max);
    return Either.left(new Failure(message, ErrorType.CONDITION_ERROR));
  }

  /**
   * Pre-spawn check for <em>parallel</em> multi-instance bodies.
   *
   * <p>Called immediately before {@code activateChildInstancesInBatches} so that the engine can
   * stop a large-collection loop before spawning the next batch of children. The check is:
   *
   * <pre>
   *   bodyCount × batchSize &gt; maxActivations  AND  bodyCount &ge; 2
   * </pre>
   *
   * <p>The {@code bodyCount ≥ 2} guard preserves correctness for legitimate large-collection
   * processes that run only once: their first (and only) body activation is always allowed through,
   * regardless of how many items the collection contains.
   *
   * <p>{@link #checkActivationThreshold} must have already been called for the same element
   * activation so that the stored body counter reflects the current iteration.
   *
   * @param context the context of the {@code MULTI_INSTANCE_BODY} element being activated
   * @param batchSize the number of child instances that would be spawned in the next batch
   * @return {@code Either.right(null)} when within the allowed bounds, or {@code Either.left} with
   *     a {@link Failure} when the threshold is exceeded
   */
  public Either<Failure, Void> checkBatchActivationThreshold(
      final BpmnElementContext context, final int batchSize) {
    final int max = resolveMaxActivations(context.getBpmnElementType());
    if (max <= 0) {
      // Loop detection is disabled for this element type.
      return Either.right(null);
    }
    final long bodyCount =
        elementInstanceState.getElementActivationCount(
            context.getProcessInstanceKey(), context.getElementId());

    final long projectedTotal = bodyCount * batchSize;
    if (projectedTotal <= max) {
      return Either.right(null);
    }

    final String elementId = BufferUtil.bufferAsString(context.getElementId());
    final String message =
        CONDITION_ERROR_BATCH_ACTIVATION_COUNT_EXCEEDED.formatted(
            elementId, context.getProcessInstanceKey(), bodyCount, batchSize, projectedTotal, max);
    return Either.left(new Failure(message, ErrorType.CONDITION_ERROR));
  }

  /**
   * Resolves the effective maximum activation count for the given element type. Returns the
   * per-type override when configured, otherwise the global default. A value of {@code 0} means
   * loop detection is disabled for that type.
   */
  private int resolveMaxActivations(final BpmnElementType elementType) {
    final Integer override = maxActivationsByType.get(elementType);
    return override != null ? override : maxActivations;
  }
}
