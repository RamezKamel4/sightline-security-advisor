import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog";

interface ScanPermissionModalProps {
  isOpen: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  scanType: string;
}

export const ScanPermissionModal = ({ isOpen, onConfirm, onCancel, scanType }: ScanPermissionModalProps) => {
  return (
    <AlertDialog open={isOpen}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>⚠️ Scan Permission Required</AlertDialogTitle>
          <AlertDialogDescription className="space-y-4">
            <p>
              You are about to perform a <strong>{scanType}</strong> network scan.
            </p>
            <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-md p-4">
              <p className="text-sm font-semibold text-yellow-800 dark:text-yellow-200 mb-2">
                Legal Notice:
              </p>
              <ul className="text-sm text-yellow-700 dark:text-yellow-300 space-y-1 list-disc list-inside">
                <li>Only scan networks and systems you own or have explicit written permission to test</li>
                <li>Unauthorized scanning may be illegal in your jurisdiction</li>
                <li>ARP discovery and SYN scans require elevated privileges</li>
                <li>Aggressive scans may disrupt network services</li>
              </ul>
            </div>
            <p className="text-sm">
              By proceeding, you confirm that you have proper authorization to scan the target network.
            </p>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel onClick={onCancel}>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={onConfirm}>
            I Have Permission - Start Scan
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
};
