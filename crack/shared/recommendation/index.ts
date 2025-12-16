/**
 * Recommendation Engine Module
 *
 * Exports the recommendation engine and types for B.R.E.A.C.H.
 */

export {
  detectPhase,
  getPhaseReason,
  getRecommendations,
  getPhaseLabel,
} from './engine';

export type {
  AttackPhase,
  RecommendedAction,
  RecommendationResult,
  RecommendationContext,
} from '../types/recommendation';

export { PHASE_LABELS } from '../types/recommendation';
