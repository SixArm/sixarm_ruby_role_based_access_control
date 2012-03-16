# -*- coding: utf-8 -*-
=begin rdoc
Please see README
=end


class RoleBasedAccessControl


  ##########################################################################
  #
  #  ANSI
  #
  ##########################################################################


  public


  # This command creates a new RBAC user.
  #
  # The command is valid only if:
  # - the new user is not already a member of the /USERS/ data set.
  #
  # The /USER/ data set is updated.
  #
  # The new user does not own any session at the time of its creation.

  def add_user(user)
    valid_only_if(!users_include?(user))
  end


  # This command deletes an existing user from the RBAC database.
  #
  # The command is valid if and only if:
  # - the user to be deleted is a member of the /USERS/ data set.
  #
  # The /USERS/ and /UA/  data sets and the /assigned_users/ function are updated.
  #
  # It is an implementation decision how to proceed with the sessions owned by the
  # user to be deleted. The RBAC system could wait for such a session to terminate
  # normally, or it could force its termination.

  def delete_user(user)
    valid_iff(users_include?(user))
  end


  # This command creates a new role.
  #
  # The command is valid if and only if:
  # - the new role is not already a member of the /ROLES/ data set.
  #
  # The /ROLES/ data set and the functions /assigned_users/ and /assigned_permissions/ are updated.
  #
  # Initially, no user or permission is assigned to the new role.

  def add_role(role)
    valid_iff(!roles_include?(role))
  end


  # This command deletes an existing role from the RBAC database.
  #
  # The command is valid if and only if
  # - the role to be deleted is a member of the /ROLES/ data set.
  #
  # It is an implementation decision how to proceed with the sessions in which the
  # role to be deleted is active. The RBAC system could wait for such a session to
  # terminate normally, it could force the termination of that session, or it could
  # delete the role from that session while allowing the session to continue.

  def delete_role(role)
    valid_iff(roles_include?(role))
  end


  # This command assigns a user to a role.
  #
  # The command is valid if and only if:
  # - the user is a member of the /USERS/ data set
  # - the role is a member of the /ROLES/ data set
  # - the user is not already assigned to the role
  #
  # The data set UA and the function assigned_users are updated to reflect the assignment.

  def assign_user(user,role)
    valid_iff(users_include?(user) && roles_include?(role))
  end


  # This command deletes the assignment of the user user to the role role.
  #
  # The command is valid if and only if:
  # - the user is a member of the USERS data set
  # - the role is a member of the ROLES data set
  # - and the user is assigned to the role
  #
  # It is an implementation decision how to proceed with the sessions in which the session
  # user is user and one of his/her active roles is role. The RBAC system could wait for such
  # a session to terminate normally, could force its termination, or could inactivate the role.

  def deassign_user(user,role)
    valid_iff(users_include?(user) && roles_include?(role) && user_role_assignments_include?(user,role))
  end


  # This command grants a role the permission to perform an operation on an object to a role.
  #
  # The command may be implemented as granting permissions to a group corresponding to
  # that role, i.e., setting the access control list of the object involved.
  #
  # The command is valid if and only if:
  # - the pair (operation, object) represents a permission
  # - the role is a member of the ROLES data set.

  def grant_permission(object,operation,role)
    valid_iff(permissions_include?(operation,object) && roles_include?(role))
  end


  # This command revokes the permission to perform an operation on an object from the set
  # of permissions assigned to a role. The command may be implemented as revoking
  # permissions from a group corresponding to that role, i.e., setting the access control list of
  # the object involved.
  #
  # The command is valid if and only if:
  # - the pair (operation, object) represents a permission
  # - the role is a member of the ROLES data set.

  def revoke_permission(object,operation,role)
    valid_iff(permissions_include?([object,operation]) && roles_include?(role))
  end


  # This function creates a new session with a given user as owner and an active role set.
  #
  # The function is valid if and only if:
  # - the user is a member of the USERS data set, and
  # - the active role set is a subset of the roles assigned to that user.
  #
  # In a RBAC implementation, the session’s active roles might actually be the
  # groups that represent those roles.

  def create_session(user,session)
    valid_iff(users_include?(user) && active_role_set_is_subset_of_roles_assigned_to_user(user))
  end


  # This function deletes a given session with a given owner user.
  #
  # The function is valid if and only if:
  # - the user is a member of the USERS data set
  # - the session identifier is a member of the SESSIONS data set
  # - the session is owned by the given user

  def delete_session(user,session)
    valid_iff(users_include?(user) && sessions_include?(session) && user_owns_session?(user,session))
  end


  # This function adds a role as an active role of a session whose owner is a given user.
  #
  # The function is valid if and only if:
  # - the user is a member of the USERS data set
  # - the session identifier is a member of the SESSIONS data set
  # - the role is a member of the ROLES data set
  # - the role is assigned to the user
  # - the session is owned by that user
  #
  # In an implementation, the new active role might be a group that corresponds to that role.

  def add_active_role(user,session,role)
    valid_iff(users_include?(user) && sessions_include?(sessions) && roles_include?(role) && user_role_assignments_include?(user,role) && user_owns_session?(user,session))
  end


  # This function deletes a role from the active role set of a session owned by a given user.
  #
  # The function is valid if and only if:
  # - the user is a member of the USERS data set
  # - the session identifier is a member of the SESSIONS data set
  # - the role is a member of the ROLES data set
  # - the session is owned by the user
  # - the role is an active role of that session.

  def drop_active_role(user,session,role)
    valid_iff(users_include?(user) && sessions_include?(sessions) && roles_include?(role) && user_owns_session?(user,session) && active_roles_include?(role,session))
  end


  # This function returns a Boolean value meaning whether the subject of a given session is
  # allowed or not to perform a given operation on a given object.
  #
  # The function is valid if and only if:
  # - the session identifier is a member of the SESSIONS data set
  # - the operation is a member of the OPS data set
  # - the object is a member of the OBJS data set
  #
  # The session’s subject has the permission to perform the operation on that object if and only if
  # that permission is assigned to (at least) one of the session’s active roles.
  #
  # An implementation might use the groups that correspond to the subject’s active roles and
  # their permissions as registered in the object’s access control list.

  def check_access(session,operation,object) #=> boolean
    valid_iff(sessions_include?(session) && operations_include?(operation) && objects_include?(object))
  end


  # This function returns the set of users assigned to a given role.
  #
  # The function is valid if and only if:
  # - the role is a member of the ROLES data set

  def assigned_users(role) #=> users
    valid_iff(roles_include?(role))
  end


  # This function returns the set of roles assigned to a given user.
  #
  # The function is valid if and only if:
  # - the user is a member of the USERS data set

  def assigned_roles(user) #=> roles
    valid_iff(users_include?(user))
  end


  # This function returns the set of all permissions (op, obj),
  # granted to or inherited by a given role.
  #
  # The function is valid if and only if:
  # - the role is a member of the ROLES data set

  def role_permissions(role) #=> permissions
    valid_iff(roles_include?(role))
  end


  # This function returns the permissions a given user gets through his/her authorized roles.
  #
  # The function is valid if and only if:
  # - the user is a member of the USERS data set.

  def user_permissions(user) #=> permissions
    valid_iff(users_include?(user))
  end


  # This function returns the active roles associated with a session.
  #
  # The function is valid if and only if:
  # - the session identifier is a member of the SESSIONS data set

  def session_roles(session) #=> roles
    valid_iff(sessions_include?(session))
  end


  # This function returns the permissions of the session session,
  # i.e., the permissions assigned to its active roles.
  #
  # The function is valid if and only if:
  # - the session identifier is a member of the SESSIONS data set

  def session_permissions(session) #=> permissions
    valid_iff(sessions_include?(session))
  end


  # This function returns the set of operations a given role is permitted to perform on a given object.
  # The set contains all operations granted directly to that role or inherited by that role from other roles.
  #
  # The function is valid only if:
  # - the role is a member of the ROLES data set
  # - the object is a member of the OBJS data set

  def role_operations_on_object(role,object) #=> operations
    valid_iff(roles_include?(role) && objects_include?(object))
  end


  # This function returns the set of operations a given user is permitted to perform on a given object.
  # The set consists of all the operations obtained by the user either directly, or through his/her authorized roles.
  #
  # The function is valid if and only if:
  # - the user is a member of the USERS data set
  # - the object is a member of the OBJS data set

  def user_operations_on_object(user,object) #=> operations
    valid_iff(users_include?(user) && objects_include?(object))
  end


  ##########################################################################
  #
  #  6.2 Hierarchical RBAC
  #
  ##########################################################################

  #### Possible future upgrade for Hierarchical RBAC goes here



  ##########################################################################
  #
  # 6.3 Static Separation of Duty (SSD)
  #
  # The static separation of duty property, as defined in the model,
  # uses a collection SSD of pairs of a role set and an associated
  # cardinality. This section defines the new data type SSD, which
  # in an implementation could be the set of names used to identify
  # the pairs in the collection.
  #
  ##########################################################################

  #### Possible future upgrade for Static Separation of Duty (SSD) goes here


  ##########################################################################
  #
  # 6.4 Dynamic Separation of Duty (SSD)
  #
  # The dynamic separation of duty property, as defined in the model,
  # uses a collection DSD of pairs of a role set and an associated
  # cardinality. This section defines the new data type DSD, which
  # in an implementation could be the set of names used to identify
  # the pairs in the collection.
  #
  ##########################################################################

  #### Possible future upgrade for Dynamic Separation of Duty (SSD) goes here




  ##########################################################################
  #
  #  Helpers for Validating Input
  #
  ##########################################################################


  public

  class RoleBasedAccessControlInvalidArgumentError < ArgumentError
  end

  protected


  def valid_only_if(condition)
    condition or raise RoleBasedAccessControlInvalidArgumentError
  end


  def valid_iff(condition)
    condition or raise RoleBasedAccessControlInvalidArgumentError
  end



  ##########################################################################
  #
  #  Helpers
  #
  ##########################################################################


  protected


  # Return the USERS data set.
  #
  # Optional for implementations.

  def users() #=> users
  end


  # Set the USERS data set.
  #
  # Optional for implementations.

  def users=(users)
  end


  # Return true iff the user is a member of the USERS data set.
  #
  # Required for implementations.

  def users_include?(user)
  end


  # Return the ROLES data set.
  #
  # Optional for implementations.

  def roles() #=> roles
  end


  # Set the ROLES data set.
  #
  # Optional for implementations.

  def roles=(roles)
  end


  # Return true iff the role is a member of the ROLES data set.
  #
  # Required for implementations.

  def roles_include?(role)
  end


  # Return the PERMISSIONS data set.
  #
  # Optional for implementations.

  def permissions() #=> permissions
  end


  # Set the PERMISSIONS data set.
  #
  # Optional for implementations.

  def permissions=(permissions)
  end


  # Return true iff the permission is a member of the PERMISSIONS data set.
  #
  # Required for implementations.

  def permissions_include?(permission)
  end


  # Return the SESSIONS data set.
  #
  # Optional for implementations.

  def sessions() #=> sessions
  end

  # Set the SESSIONS data set.
  #
  # Optional for implementations.

  def sessions=(sessions)
  end


  # Return true iff the session is a member of the SESSIONS data set.
  #
  # Required for implementations.

  def sessions_include?(session)
  end


  # Return the ACTIVE_ROLES data set for the session.
  #
  # Optional for implementations.

  def active_roles(session) #=> roles
  end


  # Return true iff the role is an active role of the session.
  #
  # Required for implementations.

  def active_roles_include?(role,session)
  end


  # Return the set of user role assignments.
  #
  # Optional for implementations.

  def user_role_assignments() #=> assignments
  end


  # Set the user role assignments data set.
  #
  # Optional for implementations.

  def user_role_assignments=(user_role_assignments)
  end


  # Return true iff the user is assigned to the role.
  #
  # Required for implementations.

  def user_role_assignments_include?(user,role)
  end


  # Return true iff the active role set is a subset of the roles assigned to that user.
  #
  # Required for implementations.

  def active_role_set_is_subset_of_roles_assigned_to_user?(user)
  end


  # Return true iff the user owns the session.
  #
  # Required for implementations.
  def user_owns_session?(user,session)
  end


end

