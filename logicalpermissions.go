package logicalpermissions

import (
  "fmt"
  "encoding/json"
  "strconv"
)

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

func (this *LogicalPermissions) RemoveType(name string) error {
  if name == "" {
    return &InvalidArgumentValueError{"The name parameter cannot be empty."}  
  }
  exists, _ := this.TypeExists(name)
  if(!exists) {
    return &PermissionTypeNotRegisteredError{fmt.Sprintf("The permission type \"%s\" has not been registered. Please use LogicalPermissions::AddType() or LogicalPermissions::SetTypes() to register permission types.", name)}  
  }
  types := this.GetTypes()
  delete(types, name)
  this.SetTypes(types)
  return nil
}

func (this *LogicalPermissions) TypeExists(name string) (bool, error) {
  if name == "" {
    return false, &InvalidArgumentValueError{"The name parameter cannot be empty."}
  }
  types := this.GetTypes()
  if _, ok := types[name]; ok {
    return true, nil
  }
  return false, nil
}

func (this *LogicalPermissions) GetTypeCallback(name string) (func(string, map[string]interface{}) bool, error) {
  if name == "" {
    return nil, &InvalidArgumentValueError{"The name parameter cannot be empty."}
  }
  exists, _ := this.TypeExists(name)
  if(!exists) {
    return nil, &PermissionTypeNotRegisteredError{fmt.Sprintf("The permission type \"%s\" has not been registered. Please use LogicalPermissions::AddType() or LogicalPermissions::SetTypes() to register permission types.", name)}
  }
  types := this.GetTypes()
  return types[name], nil
}

func (this *LogicalPermissions) GetTypes() map[string]func(string, map[string]interface{}) bool {
  if this.types == nil {
    this.types = make(map[string]func(string, map[string]interface{}) bool)
  }
  types := make(map[string]func(string, map[string]interface{}) bool)
  for name, callback := range this.types {
    types[name] = callback
  }
  return types
}

func (this *LogicalPermissions) SetTypes(types map[string]func(string, map[string]interface{}) bool) error {
  for name, _ := range types {
    if name == "" {
      return &InvalidArgumentValueError{"The name parameter cannot be empty."}
    }
  }

  this.types = make(map[string]func(string, map[string]interface{}) bool)
  for name, callback := range types {
    this.types[name] = callback
  }
  return nil
}

func (this *LogicalPermissions) GetBypassCallback() func(map[string]interface{}) bool {
  return this.bypass_callback
}

func (this *LogicalPermissions) SetBypassCallback(callback func(map[string]interface{}) bool) {
  this.bypass_callback = callback
}

func (this *LogicalPermissions) CheckAccess(json_permissions string, context map[string]interface{}) (bool, error) {
  access := false
  allow_bypass := false
  var permissions map[string]interface{}
  err := json.Unmarshal([]byte(json_permissions), &permissions)
  if err != nil {
    return false, &InvalidArgumentValueError{fmt.Sprintf("Error in parsing json_permissions: %s", err)}
  }
  if val, ok := permissions["no_bypass"]; ok {
    switch val.(type) {
      case bool:
        allow_bypass = !permissions["no_bypass"]
      case map[string]interface{}:
        allow_bypass, err = !this.processOR(permissions.no_bypass, nil, context)
        if err != nil {
          return false, &InvalidArgumentValueError(fmt.Sprintf("Error parsing no_bypass object: %s", err))
        }
      default:
        return false, &InvalidArgumentValueError{fmt.Sprintf("The no_bypass value must be a boolean or a json object. Current value: %v", val)}
    }
    delete(permissions["no_bypass"])
    
    if allow_bypass {
    access, err = this.checkBypassAccess(context)
      if err != nil {
        return false, &InvalidArgumentValueError(fmt.Sprintf("Error checking bypass access: %s", err))
      }
    }
    if !access {
      if len(permissions) > 0 {
        access, err = this.processOR(permissions, nil, context)
        if err != nil {
          return false, &InvalidArgumentValueError(fmt.Sprintf("Error checking access: %s", err))
        }
      }
    }
  }
  return access, nil
}

func (this *LogicalPermissions) dispatch(permissions interface{}, type string, context map[string]interface{}) (bool, error) {
  access := false
  err := make(error)
  switch permissions.(type) {
    case string:
      access, err = externalAccessCheck(permissions, type, context)
      if err != nil {
        return false, &InvalidArgumentValueError(fmt.Sprintf("%s", err))
      }
    case []interface{}:
      if len(permissions) > 0 {
        access, err = this.processOR(permissions, type, context) 
        if err != nil {
          return false, &InvalidArgumentValueError(fmt.Sprintf("%s", err))
        }
      }
    case map[string]interface{}:
      if len(permissions) == 1 {
        key := ""
        for k, _ := range permissions {
          key = k
          break
        }
        value := permissions[key]
        if key == "AND" {
          access, err = this.processAND(value, type, context)
          if err != nil {
            return false, &InvalidArgumentValueError(fmt.Sprintf("%s", err))
          }
        }
        else if key == "NAND" {
          access, err = this.processNAND(value, type, context)
          if err != nil {
            return false, &InvalidArgumentValueError(fmt.Sprintf("%s", err))
          }
        }
        else if key == "OR" {
          access, err = this.processOR(value, type, context)
          if err != nil {
            return false, &InvalidArgumentValueError(fmt.Sprintf("%s", err))
          }
        }
        else if key == "NOR" {
          access, err = this.processNOR(value, type, context)
          if err != nil {
            return false, &InvalidArgumentValueError(fmt.Sprintf("%s", err))
          }
        }
        else if key == "XOR" {
          access, err = this.processXOR(value, type, context)
          if err != nil {
            return false, &InvalidArgumentValueError(fmt.Sprintf("%s", err))
          }
        }
        else if key == "NOT" {
          access, err = this.processNOT(value, type, context)
          if err != nil {
            return false, &InvalidArgumentValueError(fmt.Sprintf("%s", err))
          }
        }
        else {
          if _, err2 := strconv.Atoi(v); err2 == nil {
            if type == nil {
              type = key 
            }
            else {
              return false, &InvalidArgumentValueError(fmt.Sprintf("You cannot put a permission type as a descendant to another permission type. Existing type: %s. Evaluated permissions: %v", type, permissions))
            }
          }
          if value.(type) == []interface{} || value.(type) == map[string]interface{} {
            access, err = this.processOR(value, type, context)
            if err != nil {
              return false, &InvalidArgumentValueError(fmt.Sprintf("%s", err))
            }
          }
          else {
            access, err = this.dispatch(value, type, context)
            if err != nil {
              return false, &InvalidArgumentValueError(fmt.Sprintf("%s", err))
            }
          }
        }
      }s
      else if len(permissions) > 1 {
        access, err = this.processOR(permissions, type, context) 
        if err != nil {
          return false, &InvalidArgumentValueError(fmt.Sprintf("%s", err))
        }
      }
    default:
      return false, &InvalidArgumentValueError(fmt.Sprintf("A permission value must either be a string, an array or an object. Evaluated permissions: %v", permissions))
  }
  return access, nil
}

func (this *LogicalPermissions) processAND(permissions interface{}, type string, context map[string]interface{}) (bool, error) {
  
}

func (this *LogicalPermissions) processNAND(permissions interface{}, type string, context map[string]interface{}) (bool, error) {
  
}

func (this *LogicalPermissions) processOR(permissions interface{}, type string, context map[string]interface{}) (bool, error) {
  
}

func (this *LogicalPermissions) processNOR(permissions interface{}, type string, context map[string]interface{}) (bool, error) {
  
}

func (this *LogicalPermissions) processXOR(permissions interface{}, type string, context map[string]interface{}) (bool, error) {
  
}

func (this *LogicalPermissions) processNOT(permissions interface{}, type string, context map[string]interface{}) (bool, error) {
  
}

func (this *LogicalPermissions) externalAccessCheck(permission string, type string, context map[string]interface{}) (bool, error) {
  
}