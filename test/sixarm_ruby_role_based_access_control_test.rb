require 'test/unit'
require 'sixarm_ruby_role_based_access_control'

class RoleBasedAccessControlTest < Test::Unit::TestCase

  def setup
    @rbac = RoleBasedAccessControl.new
    @user='user_1'
    @role='role_1'
    @object='object_1'
    @permission='permission_1'
    @operation='operation_1'
    @session='session_1'
    @active_role='active_role_1'
    @users=['user_1','user_2','user_3']
    @roles=['role_1','role_2','role_3']
    @permissions=['permission_1','permission_2','permission_3']
    @sessions=['session_1','session_2','session_3']
    @operations=['operation_1','operation_2','operation_3']
    @active_roles=['active_role_1','active_role_2','active_role_3']
  end

  #######################################################################################
  #
  # Test validity methods first
  #
  #######################################################################################

  def test_valid_iff_true
    assert_nothing_raised do
      valid_only_iff(true)
    end
  end

  def test_valid_iff_false
    assert_raise RoleBasedAccessControlInvalidArgumentError do
      valid_only_iff(false)
    end
  end

  def test_valid_only_if_true
    assert_nothing_raised do
      valid_only_if(false)
    end
  end

  def test_valid_only_if_false
    assert_raise RoleBasedAccessControlInvalidArgumentError do
      valid_only_if(false)
    end
  end

  #######################################################################################
  #
  # ANSI
  #
  #######################################################################################

  def test_add_user
    assert_raise RoleBasedAccessControlInvalidArgumentError do
      add_user(@user)
    end
  end

  def test_delete_user
    assert_raise RoleBasedAccessControlInvalidArgumentError do
      delete_user(@user)
    end
  end

  def test_add_role
    assert_raise RoleBasedAccessControlInvalidArgumentError do 
      add_role(@role)
    end
  end

  def test_delete_user
    assert_raise RoleBasedAccessControlInvalidArgumentError do
      delete_role(@role)
    end
  end

  def test_assign_user
    assert_raise RoleBasedAccessControlInvalidArgumentError do
      assign_user(@user,@role)
    end
  end

  def test_deassign_user
    assert_raise RoleBasedAccessControlInvalidArgumentError do
      deassign_user(@user,@role)
    end
  end

  def test_grant_permission
    assert_raise RoleBasedAccessControlInvalidArgumentError do
      grant_permission(@object,@operation,@role)
    end
  end

  def test_revoke_permission
    assert_raise RoleBasedAccessControlInvalidArgumentError do 
      revoke_permission(@object,@operation,@role)
    end
  end

  def test_create_session
    assert_raise RoleBasedAccessControlInvalidArgumentError do 
      create_session(@user,@session)
    end
  end

  def test_delete_session
    assert_raise RoleBasedAccessControlInvalidArgumentError do
      delete_session(@user,@session)
    end
  end

  def test_add_active_role
    assert_raise RoleBasedAccessControlInvalidArgumentError do 
      add_active_role(@user,@session,@role)
    end
  end

  def test_drop_active_role
    assert_raise RoleBasedAccessControlInvalidArgumentError do 
      drop_active_role(@user,@session,@role)
    end
  end

  def test_check_access
   assert_raise RoleBasedAccessControlInvalidArgumentError do 
     check_access(@session,@operation,@object)
   end
  end

  def test_assigned_users
   assert_raise RoleBasedAccessControlInvalidArgumentError do 
     assigned_users(@role)
   end
  end

  def test_assigned_roles
   assert_raise RoleBasedAccessControlInvalidArgumentError do 
     assigned_roles(@user)
   end
  end

  def test_user_permissions
   assert_raise RoleBasedAccessControlInvalidArgumentError do 
     user_permissions(@user)
   end
  end

  def test_role_permissions
   assert_raise RoleBasedAccessControlInvalidArgumentError do 
     role_permissions(@role)
   end
  end

  def test_session_permissions
   assert_raise RoleBasedAccessControlInvalidArgumentError do
     session_permissions(@session)
   end
  end

  def test_role_operations_on_object
   assert_raise RoleBasedAccessControlInvalidArgumentError do
     role_operations_on_object(@role,@object)
   end
  end

  def test_user_operations_on_object
   assert_raise RoleBasedAccessControlInvalidArgumentError do 
     user_operations_on_object(@user,@object)
   end
  end

  #######################################################################################
  #
  # Helpers - not much to test here because implementations will do things differently.
  # 
  # We have put commented methods here as examples of what you might want to call,
  # for your own testing, if you are writing an implementation.
  #
  #######################################################################################

  def test_users
    @rbac.users=@users
    #assert_equal(@users,@rbac.users)
  end

  def test_users_include
    @rbac.users=@users
    #assert( rbac.users_include?(@user))
    #assert(!rbac.users_include?('foo'))
  end

  def test_roles
    rbac.roles=roles
    #assert_equal(roles,rbac.roles)
  end

  def test_roles_include
    @rbac.roles=@roles
    #assert( rbac.roles_include?(@role))
    #assert(!rbac.roles_include?('foo'))
  end

  def test_permissions
    @rbac.permissions=@permissions
    #assert_equal(permissions,rbac.permissions)
  end

  def test_permissions_include
    @rbac.permissions=@permissions
    #assert( rbac.permissions_include?(permission))
    #assert(!rbac.permissions_include?('foo'))
  end

  def test_sessions
    @rbac.sessions=@sessions
    #assert_equal(sessions,rbac.sessions)
  end

  def test_sessions_include
    @rbac.sessions=@sessions
    #assert( rbac.sessions_include?(session))
    #assert(!rbac.sessions_include?('foo'))
  end

  def test_active_roles
    @rbac.active_roles=@active_roles
    #assert_equal(active_roles,rbac.active_roles)
  end

  def test_active_roles_include
    @rbac.active_roles=@active_roles
    #assert( rbac.active_roles_include?(active_role))
    #assert(!rbac.active_roles_include?('foo'))
  end

  def test_user_role_assignments
    @rbac.user_role_assignments=@user_role_assignments
    #assert_equal(user_role_assignments,rbac.user_role_assignments)
  end

  def test_user_role_assignments_include
    @rbac.user_role_assignments=@user_role_assignments
    #assert( rbac.user_role_assignments?(user_role_assignment))
    #assert(!rbac.user_role_assignments_include?('foo'))
  end

  def test_active_role_set_is_subset_of_roles_assigned_to_user
    #active_role_set_is_subset_of_roles_assigned_to_user?(@user)
  end

  def test_user_owns_session
    #user_owns_session?(@user,@session)
  end


end




