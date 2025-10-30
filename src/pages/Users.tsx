import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Loader2, UserPlus, Shield, Users2 } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import CreateUserModal from '@/components/CreateUserModal';
import EditUserModal from '@/components/EditUserModal';

const Users = () => {
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState<any>(null);
  const [roleFilter, setRoleFilter] = useState<'all' | 'admin' | 'consultant'>('all');

  // Fetch all users with their roles
  const { data: users, isLoading, refetch } = useQuery({
    queryKey: ['all-users'],
    queryFn: async () => {
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) throw new Error('No session');

      const { data, error } = await supabase.functions.invoke('list-users', {
        headers: {
          Authorization: `Bearer ${session.access_token}`,
        },
      });

      if (error) throw error;
      return data.users;
    },
  });

  // Fetch scan statistics per user
  const { data: scanStats } = useQuery({
    queryKey: ['user-scan-stats'],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('scans')
        .select('user_id, status');
      
      if (error) throw error;

      const stats: Record<string, { total: number; completed: number }> = {};
      data?.forEach(scan => {
        if (!stats[scan.user_id]) {
          stats[scan.user_id] = { total: 0, completed: 0 };
        }
        stats[scan.user_id].total++;
        if (scan.status === 'completed') {
          stats[scan.user_id].completed++;
        }
      });

      return stats;
    },
  });

  const getRoleBadgeVariant = (role: string) => {
    switch (role) {
      case 'admin': return 'default';
      case 'consultant': return 'secondary';
      default: return 'outline';
    }
  };

  if (isLoading) {
    return (
      <div className="p-6 flex items-center justify-center min-h-screen">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">User Management</h1>
          <p className="text-muted-foreground">Manage platform users and their roles</p>
        </div>
        <Button onClick={() => setCreateModalOpen(true)}>
          <UserPlus className="h-4 w-4 mr-2" />
          Create User
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card 
          className={`cursor-pointer transition-all ${roleFilter === 'all' ? 'ring-2 ring-primary' : 'hover:bg-accent'}`}
          onClick={() => setRoleFilter('all')}
        >
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Users</CardTitle>
            <Users2 className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{users?.length || 0}</div>
          </CardContent>
        </Card>
        <Card 
          className={`cursor-pointer transition-all ${roleFilter === 'admin' ? 'ring-2 ring-primary' : 'hover:bg-accent'}`}
          onClick={() => setRoleFilter('admin')}
        >
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Administrators</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {users?.filter(u => u.roles.includes('admin')).length || 0}
            </div>
          </CardContent>
        </Card>
        <Card 
          className={`cursor-pointer transition-all ${roleFilter === 'consultant' ? 'ring-2 ring-primary' : 'hover:bg-accent'}`}
          onClick={() => setRoleFilter('consultant')}
        >
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Consultants</CardTitle>
            <Users2 className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {users?.filter(u => u.roles.includes('consultant')).length || 0}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>
            {roleFilter === 'all' && 'All Users'}
            {roleFilter === 'admin' && 'Administrators'}
            {roleFilter === 'consultant' && 'Consultants'}
          </CardTitle>
          <CardDescription>View and manage user accounts and permissions</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Email</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Roles</TableHead>
                <TableHead>Scans</TableHead>
                <TableHead>Last Sign In</TableHead>
                <TableHead>Joined</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users
                ?.filter(user => {
                  if (roleFilter === 'all') return true;
                  return user.roles.includes(roleFilter);
                })
                .map((user) => (
                <TableRow key={user.id}>
                  <TableCell className="font-medium">{user.email}</TableCell>
                  <TableCell>{user.profile?.name || '-'}</TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      {user.roles.length > 0 ? (
                        user.roles.map(role => (
                          <Badge key={role} variant={getRoleBadgeVariant(role)}>
                            {role}
                          </Badge>
                        ))
                      ) : (
                        <Badge variant="outline">user</Badge>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    {scanStats?.[user.id] ? (
                      <span className="text-sm">
                        {scanStats[user.id].completed}/{scanStats[user.id].total}
                      </span>
                    ) : (
                      <span className="text-sm text-muted-foreground">0/0</span>
                    )}
                  </TableCell>
                  <TableCell>
                    {user.last_sign_in_at 
                      ? new Date(user.last_sign_in_at).toLocaleDateString()
                      : 'Never'}
                  </TableCell>
                  <TableCell>
                    {new Date(user.created_at).toLocaleDateString()}
                  </TableCell>
                  <TableCell>
                    <Button 
                      variant="ghost" 
                      size="sm"
                      onClick={() => {
                        setSelectedUser(user);
                        setEditModalOpen(true);
                      }}
                    >
                      Edit
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <CreateUserModal 
        open={createModalOpen}
        onOpenChange={setCreateModalOpen}
        onSuccess={refetch}
      />

      <EditUserModal
        open={editModalOpen}
        onOpenChange={setEditModalOpen}
        user={selectedUser}
        onSuccess={refetch}
      />
    </div>
  );
};

export default Users;
