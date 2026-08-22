import { useContext } from 'react';
import { SecurityFeedContext, type SecurityFeedValue } from './securityFeedContext';

/** Access to live security state. Throws outside the provider rather than
 *  silently returning empty data, which would look like "no threats". */
export function useSecurityFeed(): SecurityFeedValue {
  const context = useContext(SecurityFeedContext);
  if (!context) {
    throw new Error('useSecurityFeed must be used inside <SecurityFeedProvider>');
  }
  return context;
}
