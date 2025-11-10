import React, { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Checkbox } from '@/components/ui/checkbox';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Loader2 } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { z } from 'zod';
import { useQuery } from '@tanstack/react-query';

const editUserSchema = z.object({
  name: z.string().trim().min(1, 'Name is required').max(100, 'Name must be less than 100 characters'),
});

interface User {
  id: string;
  email: string;
  roles: string[];
  profile?: { name: string; consultant_id?: string };
}

interface EditUserModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  user: User | null;
  onSuccess: () => void;
}

const EditUserModal = ({ open, onOpenChange, user, onSuccess }: EditUserModalProps) => {
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const [name, setName] = useState('');
  const [roles, setRoles] = useState<string[]>([]);
  const [consultantId, setConsultantId] = useState<string>('');
  const [errors, setErrors] = useState<Record<string, string>>({});

  // Fetch all consultants and admins
  const { data: consultants } = useQuery({
    queryKey: ['consultants-and-admins'],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('user_roles')
        .select('user_id, users!inner(user_id, email, name)')
        .in('role', ['consultant', 'admin']);
      
      if (error) throw error;
      
      // Remove duplicates (users with both roles)
      const uniqueUsers = new Map();
      data?.forEach(r => {
        if (r.users && !uniqueUsers.has(r.users.user_id)) {
          uniqueUsers.set(r.users.user_id, r.users);
        }
      });
      
      return Array.from(uniqueUsers.values());
    },
  });

  useEffect(() => {
    if (user) {
      setName(user.profile?.name || '');
      setRoles(user.roles || []);
      setConsultantId(user.profile?.consultant_id || '');
    }
  }, [user]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!user) return;
    
    setLoading(true);
    setErrors({});

    try {
      // Validate input
      const validatedData = editUserSchema.parse({ name });

      const { data: { session } } = await supabase.auth.getSession();
      if (!session) throw new Error('No session');

      const { data, error } = await supabase.functions.invoke('update-user-roles', {
        headers: {
          Authorization: `Bearer ${session.access_token}`,
        },
        body: {
          userId: user.id,
          name: validatedData.name,
          roles,
          consultantId: consultantId || null,
        },
      });

      if (error) throw error;

      toast({
        title: 'Success',
        description: 'User updated successfully',
      });

      onOpenChange(false);
      onSuccess();
    } catch (error: any) {
      if (error instanceof z.ZodError) {
        const fieldErrors: Record<string, string> = {};
        error.errors.forEach((err) => {
          if (err.path[0]) {
            fieldErrors[err.path[0] as string] = err.message;
          }
        });
        setErrors(fieldErrors);
      } else {
        toast({
          title: 'Error',
          description: error.message || 'Failed to update user',
          variant: 'destructive',
        });
      }
    } finally {
      setLoading(false);
    }
  };

  const toggleRole = (role: string) => {
    setRoles(prev => 
      prev.includes(role) 
        ? prev.filter(r => r !== role)
        : [...prev, role]
    );
  };

  if (!user) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle>Edit User</DialogTitle>
          <DialogDescription>
            Update user information and roles for {user.email}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="John Doe"
                maxLength={100}
              />
              {errors.name && <p className="text-sm text-destructive">{errors.name}</p>}
            </div>
            <div className="grid gap-2">
              <Label>Roles</Label>
              <div className="flex flex-col gap-2">
                <div className="flex items-center space-x-2">
                  <Checkbox 
                    id="admin" 
                    checked={roles.includes('admin')}
                    onCheckedChange={() => toggleRole('admin')}
                  />
                  <label htmlFor="admin" className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">
                    Admin
                  </label>
                </div>
                <div className="flex items-center space-x-2">
                  <Checkbox 
                    id="consultant" 
                    checked={roles.includes('consultant')}
                    onCheckedChange={() => toggleRole('consultant')}
                  />
                  <label htmlFor="consultant" className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">
                    Consultant
                  </label>
                </div>
              </div>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="consultant-select">Assign Consultant</Label>
              <Select value={consultantId || 'none'} onValueChange={(value) => setConsultantId(value === 'none' ? '' : value)}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a consultant" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">None</SelectItem>
                  {consultants?.map((consultant: any) => (
                    <SelectItem key={consultant.user_id} value={consultant.user_id}>
                      {consultant.name || consultant.email}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Consultants will review and approve AI-generated reports for this user
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={loading}>
              {loading && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              Save Changes
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
};

export default EditUserModal;
