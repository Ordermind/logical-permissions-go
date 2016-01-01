package logicalpermissions

type LogicalPermissions struct {
  types map[string]func(string, map[string]interface{}) bool
  bypass_callback func(map[string]interface{}) bool
}

func (this *LogicalPermissions) AddType(name string, callback func(string, map[string]interface{}) bool) error {
  if name == "" {
    return &InvalidArgumentValueError{"The name parameter cannot be empty."}  
  }
  types := this.GetTypes()
  types[name] = callback
  this.SetTypes(types)
  return nil
}

func (this *LogicalPermissions) RemoveType(name string) {
  
}

func (this *LogicalPermissions) TypeExists(name string) bool {
  types := this.GetTypes()
  if _, ok := types[name]; ok {
    return true
  }
  return false
}

func (this *LogicalPermissions) GetTypeCallback(name string) func(string, map[string]interface{}) bool {
  var callback func(string, map[string]interface{}) bool
  return callback
}

func (this *LogicalPermissions) GetTypes() map[string]func(string, map[string]interface{}) bool {
  if this.types == nil {
    this.types = make(map[string]func(string, map[string]interface{}) bool)
  }
  return this.types
}

func (this *LogicalPermissions) SetTypes(types map[string]func(string, map[string]interface{}) bool) {
  this.types = types
}

func (this *LogicalPermissions) GetBypassCallback() func(map[string]interface{}) bool {
  return this.bypass_callback
}

func (this *LogicalPermissions) SetBypassCallback(callback func(map[string]interface{}) bool) {
  
}

func (this *LogicalPermissions) CheckAccess(permissions map[string]interface{}, context map[string]interface{}) bool {
  access := false
  return access
}