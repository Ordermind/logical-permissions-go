package logicalpermissions

type LogicalPermissions struct {
  types map[string]interface{}
  bypass_callback func(map[string]interface{}) bool
}

func (this *LogicalPermissions) AddType(name string, callback func(string, map[string]interface{}) bool) error {
  if name == "" {
    return &InvalidArgumentValueError{"The name parameter cannot be empty."}  
  }
  return nil
}

func (this *LogicalPermissions) RemoveType(name string) {
  
}

func (this *LogicalPermissions) TypeExists(name string) bool {
  access := false
  return access
}

func (this *LogicalPermissions) GetTypeCallback(name string) func(string, map[string]interface{}) bool {
  var callback func(string, map[string]interface{}) bool
  return callback
}

func (this *LogicalPermissions) GetTypes() map[string]interface{} {
  var types map[string]interface{}
  return types
}

func (this *LogicalPermissions) SetTypes(types map[string]interface{}) {
  
}

func (this *LogicalPermissions) GetBypassCallback() func(map[string]interface{}) bool {
  var callback func(map[string]interface{}) bool
  return callback
}

func (this *LogicalPermissions) SetBypassCallback(callback func(map[string]interface{}) bool) {
  
}

func (this *LogicalPermissions) CheckAccess(permissions map[string]interface{}, context map[string]interface{}) bool {
  access := false
  return access
}