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

const createUserSchema = z.object({
  email: z.string().trim().email('Invalid email address').max(255, 'Email must be less than 255 characters'),
  name: z.string().trim().min(1, 'Name is required').max(100, 'Name must be less than 100 characters'),
});

interface CreateUserModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess: () => void;
}

const CreateUserModal = ({ open, onOpenChange, onSuccess }: CreateUserModalProps) => {
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    email: '',
    name: '',
  });
  const [roles, setRoles] = useState<string[]>([]);
  const [consultantId, setConsultantId] = useState<string>('');
  const [errors, setErrors] = useState<Record<string, string>>({});

  // Fetch all consultants
  const { data: consultants } = useQuery({
    queryKey: ['consultants'],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('user_roles')
        .select('user_id, users:user_id(user_id, email, name)')
        .eq('role', 'consultant');
      
      if (error) throw error;
      return data?.map(r => r.users).filter(Boolean) || [];
    },
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setErrors({});

    try {
      // Validate input
      const validatedData = createUserSchema.parse(formData);

      const { data: { session } } = await supabase.auth.getSession();
      if (!session) throw new Error('No session');

      const { data, error } = await supabase.functions.invoke('create-user', {
        headers: {
          Authorization: `Bearer ${session.access_token}`,
        },
        body: {
          ...validatedData,
          roles,
          consultantId: consultantId || null,
        },
      });

      if (error) throw error;

      toast({
        title: 'Success',
        description: 'User invited successfully. They will receive an email to set their password.',
      });

      setFormData({ email: '', name: '' });
      setRoles([]);
      setConsultantId('');
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
          description: error.message || 'Failed to create user',
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

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle>Create New User</DialogTitle>
          <DialogDescription>
            The user will receive an email invitation with a link to set their own password.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="name">Name</Label>
              <Input
                id="name"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="John Doe"
                maxLength={100}
              />
              {errors.name && <p className="text-sm text-destructive">{errors.name}</p>}
            </div>
            <div className="grid gap-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                placeholder="user@example.com"
                maxLength={255}
              />
              {errors.email && <p className="text-sm text-destructive">{errors.email}</p>}
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
                <div className="flex items-center space-x-2">
                  <Checkbox 
                    id="user" 
                    checked={roles.includes('user')}
                    onCheckedChange={() => toggleRole('user')}
                  />
                  <label htmlFor="user" className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70">
                    User
                  </label>
                </div>
              </div>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="consultant">Assign Consultant (Optional)</Label>
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
              Create User
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
};

export default CreateUserModal;
