'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { adminDeletePoll } from '@/app/lib/actions/admin-actions';
import { useRouter } from 'next/navigation';
import CSRFToken from '@/components/ui/csrf-token';

interface AdminDeleteButtonProps {
  pollId: string;
}

export default function AdminDeleteButton({ pollId }: AdminDeleteButtonProps) {
  const [deleteLoading, setDeleteLoading] = useState(false);
  const router = useRouter();

  const handleDelete = async () => {
    if (
      !confirm(
        'Are you sure you want to delete this poll? This action cannot be undone.',
      )
    ) {
      return;
    }

    setDeleteLoading(true);

    // Create FormData with CSRF token
    const formData = new FormData();
    formData.append('pollId', pollId);

    // Get CSRF token from hidden input
    const csrfInput = document.querySelector(
      'input[name="csrf_token"]',
    ) as HTMLInputElement;
    if (csrfInput) {
      formData.append('csrf_token', csrfInput.value);
    }

    const result = await adminDeletePoll(formData);

    if (!result.error) {
      // Refresh the page to show updated data
      router.refresh();
    } else {
      alert(`Error deleting poll: ${result.error}`);
    }

    setDeleteLoading(false);
  };

  return (
    <>
      <CSRFToken />
      <Button
        variant="destructive"
        size="sm"
        onClick={handleDelete}
        disabled={deleteLoading}
      >
        {deleteLoading ? 'Deleting...' : 'Delete'}
      </Button>
    </>
  );
}
