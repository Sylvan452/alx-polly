import { setCSRFToken } from '@/app/lib/utils/csrf';

export default async function CSRFToken() {
  const token = await setCSRFToken();
  
  return (
    <input
      type="hidden"
      name="csrf-token"
      value={token}
    />
  );
}