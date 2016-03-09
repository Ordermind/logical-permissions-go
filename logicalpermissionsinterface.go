package logicalpermissions

type LogicalPermissionsInterface interface {

  /**
   * Adds a permission type.
   * @param {string} name - The name of the permission type
   * @param {func(string, map[string]interface{}) (bool, error)} callback - The callback that evaluates the permission type. Upon calling CheckAccess() the registered callback will be passed two parameters: a permission string (such as a role) and the context map passed to CheckAccess(). The permission will always be a single string even if for example multiple roles are accepted. In that case the callback will be called once for each role that is to be evaluated. The callback should return a boolean which determines whether access should be granted. It should also return an error, or nil if no error occurred.
   * @returns {error} if something goes wrong, or nil if no error occurs.
   */
  AddType(name string, callback func(string, map[string]interface{}) (bool, error)) error
  
  /**
   * Removes a permission type.
   * @param {string} name - The name of the permission type.
   * @returns {error} if something goes wrong, or nil if no error occurs.
   */
  RemoveType(name string) error
  
  /**
   * Checks whether a permission type is registered.
   * @param {string} name - The name of the permission type.
   * @returns {bool} true if the type is found or false if the type isn't found.
   * @returns {error} if something goes wrong, or nil if no error occurs.
   */
  TypeExists(name string) (bool, error)
  
  /**
   * Gets the callback for a permission type.
   * @param {string} name - The name of the permission type.
   * @returns {func(string, map[string]interface{}) (bool, error)} Callback for the permission type.
   * @returns {error} if something goes wrong, or nil if no error occurs.
   */
  GetTypeCallback(name string) (func(string, map[string]interface{}) (bool, error), error)
  
  /**
   * Changes the callback for an existing permission type.
   * @param {string} name - The name of the permission type.
   * @param {func(string, map[string]interface{}) (bool, error)} callback - The callback that evaluates the permission type. Upon calling CheckAccess() the registered callback will be passed two parameters: a permission string (such as a role) and the context map passed to CheckAccess(). The permission will always be a single string even if for example multiple roles are accepted. In that case the callback will be called once for each role that is to be evaluated. The callback should return a boolean which determines whether access should be granted. It should also return an error, or nil if no error occurred.
   * @returns {error} if something goes wrong, or nil if no error occurs.
   */
  SetTypeCallback(name string, callback func(string, map[string]interface{}) (bool, error)) error
  
  /**
   * Gets all defined permission types.
   * @returns {map[string]func(string, map[string]interface{}) (bool, error)} permission types with the structure {"name": callback, "name2": callback2, ...}. This map is shallow copied.
   */
  GetTypes() map[string]func(string, map[string]interface{}) (bool, error)
  
  /**
   * Overwrites all defined permission types.
   * @param {map[string]func(string, map[string]interface{}} types - permission types with the structure {"name": callback, "name2": callback2, ...}. This map is shallow copied.
   * @returns {error} if something goes wrong, or nil if no error occurs.
   */
  SetTypes(types map[string]func(string, map[string]interface{}) (bool, error)) error
  
  /**
   * Gets the current bypass access callback.
   * @returns {func(map[string]interface{}) (bool, error)} callback for checking access bypass.
   */
  GetBypassCallback() func(map[string]interface{}) (bool, error)
  
  /**
   * Sets the bypass access callback.
   * @param {func(map[string]interface{}) (bool, error)} callback - The callback that evaluates access bypassing. Upon calling CheckAccess() the registered bypass callback will be passed one parameter, which is the context map passed to CheckAccess(). It should return a boolean which determines whether bypass access should be granted. It should also return an error, or nil if no error occurred.
   */
  SetBypassCallback(callback func(map[string]interface{}) (bool, error))
  
  /**
   * Gets all keys that can be part of a permission tree.
   * @returns []string valid permission keys
   */
  GetValidPermissionKeys() []string
  
  /**
   * Checks access for a permission tree.
   * @param {map[string]interface{} or json string} permissions - The permission tree to be evaluated. The permission tree can either be a map or a string containing a json object.
   * @param {map[string]interface{}} context - A context map that could for example contain the evaluated user and document.
   * @param {bool} allow_bypass - Determines whether bypassing access should be allowed. Set this to true for normal behavior.
   * @returns {bool} true if access is granted or false if access is denied.
   * @returns {error} if something goes wrong, or nil if no error occurs.
   */
  CheckAccess(permissions interface{}, context map[string]interface{}, allow_bypass bool) (bool, error)
} 
