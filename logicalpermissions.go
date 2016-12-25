package logicalpermissions

import (
  "fmt"
  "encoding/json"
  "strconv"
)

type LogicalPermissions struct {
  types map[string]func(string, map[string]interface{}) (bool, error)
  bypass_callback func(map[string]interface{}) (bool, error)
}

func (this *LogicalPermissions) AddType(name string, callback func(string, map[string]interface{}) (bool, error)) error {
  if name == "" {
    return &InvalidArgumentValueError{CustomError{"The name parameter cannot be empty."}}
  }
  for _, v := range this.getCorePermissionKeys() {
    if (v == name) {
      return &InvalidArgumentValueError{CustomError{fmt.Sprintf("The name parameter has the illegal value \"%s\". It cannot be one of the following values: %v", name, this.getCorePermissionKeys())}}
    }
  }
  exists, _ := this.TypeExists(name)
  if exists {
    return &PermissionTypeAlreadyExistsError{CustomError{fmt.Sprintf("The permission type \"%s\" already exists! If you want to change the callback for an existing type, please use LogicalPermissions::SetTypeCallback().", name)}}
  }

  types := this.GetTypes()
  types[name] = callback
  this.SetTypes(types)
  return nil
}

func (this *LogicalPermissions) RemoveType(name string) error {
  if name == "" {
    return &InvalidArgumentValueError{CustomError{"The name parameter cannot be empty."}}
  }
  exists, _ := this.TypeExists(name)
  if(!exists) {
    return &PermissionTypeNotRegisteredError{CustomError{fmt.Sprintf("The permission type \"%s\" has not been registered. Please use LogicalPermissions::AddType() or LogicalPermissions::SetTypes() to register permission types.", name)}}
  }
  types := this.GetTypes()
  delete(types, name)
  this.SetTypes(types)
  return nil
}

func (this *LogicalPermissions) TypeExists(name string) (bool, error) {
  if name == "" {
    return false, &InvalidArgumentValueError{CustomError{"The name parameter cannot be empty."}}
  }
  types := this.GetTypes()
  if _, ok := types[name]; ok {
    return true, nil
  }
  return false, nil
}

func (this *LogicalPermissions) GetTypeCallback(name string) (func(string, map[string]interface{}) (bool, error), error) {
  if name == "" {
    return nil, &InvalidArgumentValueError{CustomError{"The name parameter cannot be empty."}}
  }
  exists, _ := this.TypeExists(name)
  if(!exists) {
    return nil, &PermissionTypeNotRegisteredError{CustomError{fmt.Sprintf("The permission type \"%s\" has not been registered. Please use LogicalPermissions::AddType() or LogicalPermissions::SetTypes() to register permission types.", name)}}
  }
  types := this.GetTypes()
  return types[name], nil
}

func (this *LogicalPermissions) SetTypeCallback(name string, callback func(string, map[string]interface{}) (bool, error)) error {
  if name == "" {
    return &InvalidArgumentValueError{CustomError{"The name parameter cannot be empty."}}
  }
  exists, _ := this.TypeExists(name)
  if(!exists) {
    return &PermissionTypeNotRegisteredError{CustomError{fmt.Sprintf("The permission type \"%s\" has not been registered. Please use LogicalPermissions::AddType() or LogicalPermissions::SetTypes() to register permission types.", name)}}
  }
  types := this.GetTypes()
  types[name] = callback
  this.SetTypes(types)
  return nil
}

func (this *LogicalPermissions) GetTypes() map[string]func(string, map[string]interface{}) (bool, error) {
  if this.types == nil {
    this.types = make(map[string]func(string, map[string]interface{}) (bool, error))
  }
  types := make(map[string]func(string, map[string]interface{}) (bool, error))
  for name, callback := range this.types {
    types[name] = callback
  }
  return types
}

func (this *LogicalPermissions) SetTypes(types map[string]func(string, map[string]interface{}) (bool, error)) error {
  for name, _ := range types {
    if name == "" {
      return &InvalidArgumentValueError{CustomError{"The name for a type cannot be empty."}}
    }
    for _, v := range this.getCorePermissionKeys() {
      if (v == name) {
        return &InvalidArgumentValueError{CustomError{fmt.Sprintf("The name for a type has the illegal value \"%s\". It cannot be one of the following values: %v", name, this.getCorePermissionKeys())}}
      }
    }
  }

  this.types = make(map[string]func(string, map[string]interface{}) (bool, error))
  for name, callback := range types {
    this.types[name] = callback
  }
  return nil
}

func (this *LogicalPermissions) GetBypassCallback() func(map[string]interface{}) (bool, error) {
  return this.bypass_callback
}

func (this *LogicalPermissions) SetBypassCallback(callback func(map[string]interface{}) (bool, error)) {
  this.bypass_callback = callback
}

func (this *LogicalPermissions) GetValidPermissionKeys() []string {
  core_keys := this.getCorePermissionKeys()
  types := this.GetTypes()
  type_keys := make([]string, len(types))
  i := 0
  for k := range types {
    type_keys[i] = k
    i++
  }
  return append(core_keys, type_keys...)
}

func (this *LogicalPermissions) CheckAccess(permissions interface{}, context map[string]interface{}) (bool, error) {
  return this.checkAccess(permissions, context, true)
}

func (this *LogicalPermissions) CheckAccessNoBypass(permissions interface{}, context map[string]interface{}) (bool, error) {
  return this.checkAccess(permissions, context, false)
}

func (this *LogicalPermissions) checkAccess(permissions interface{}, context map[string]interface{}, allow_bypass bool) (bool, error) {
  map_permissions, err := this.preparePermissions(permissions)
  if err != nil {
    return false, err
  }

  //Bypass access check
  if no_bypass, ok := map_permissions["no_bypass"]; ok {
    if allow_bypass {
      result, err_custom := this.checkAllowBypass(no_bypass, context)
      if err_custom != nil {
        return false, err_custom
      }
      allow_bypass = result
    }
    delete(map_permissions, "no_bypass")
  }
  if allow_bypass {
    access, err_custom := this.checkBypassAccess(context)
    if err_custom != nil {
      err_custom.setMessage(fmt.Sprintf("Error checking bypass access: %s", err_custom.Error()))
      return false, err_custom
    }
    if access {
      return access, nil
    }
  }

  //Normal access check
  if len(map_permissions) > 0 {
    access, err_custom := this.processOR(map_permissions, "", context)
    if err_custom != nil {
      err_custom.setMessage(fmt.Sprintf("Error checking access: %s", err_custom.Error()))
      return false, err_custom
    }
    return access, nil
  }

  return false, nil
}

func (this *LogicalPermissions) getCorePermissionKeys() []string {
  return []string{"no_bypass", "AND", "NAND", "OR", "NOR", "XOR", "NOT", "TRUE", "FALSE"}
}

func (this *LogicalPermissions) preparePermissions(permissions interface{}) (map[string]interface{}, error) {
  json_permissions := ""
  if map_permissions, okMap := permissions.(map[string]interface{}); okMap {
    tmpMap, err := json.Marshal(map_permissions)
    if err != nil {
      return nil, &InvalidArgumentValueError{CustomError{fmt.Sprintf("Could not convert permissions to json object: %s. Evaluated permissions: %v", err.Error(), map_permissions)}}
    }
    json_permissions = string(tmpMap)
  } else if slice_permissions, okSlice := permissions.([]interface{}); okSlice {
    tmpSlice, err := json.Marshal(slice_permissions)
    if err != nil {
      return nil, &InvalidArgumentValueError{CustomError{fmt.Sprintf("Could not convert permissions to json object: %s. Evaluated permissions: %v", err.Error(), slice_permissions)}}
    }
    json_permissions = string(tmpSlice)
  } else if tmpString, okString := interface{}(permissions).(string); okString {
    json_permissions = tmpString
  } else if tmpBool, okBool := interface{}(permissions).(bool); okBool {
    if tmpBool == true {
      json_permissions = "TRUE"
    } else if tmpBool == false {
      json_permissions = "FALSE"
    }
  } else {
    return nil, &CustomError{fmt.Sprintf("permissions must be a boolean, a string, a slice or a map[string]interface{}. Evaluated permissions: %v", permissions)}
  }

  map_permissions := make(map[string]interface{})
  err := json.Unmarshal([]byte(json_permissions), &map_permissions)
  if err != nil {
    return nil, &InvalidArgumentValueError{CustomError{fmt.Sprintf("Error parsing json permissions: %s. Evaluated permissions: %s", err.Error(), json_permissions)}}
  }
  return map_permissions, nil
}

func (this *LogicalPermissions) checkAllowBypass(no_bypass interface{}, context map[string]interface{}) (bool, CustomErrorInterface) {
  if boolval, ok := no_bypass.(bool); ok {
    return !boolval, nil
  }
  if mapval, ok := no_bypass.(map[string]interface{}); ok {
    result, err_custom := this.processOR(mapval, "", context)
    if err_custom != nil {
      err_custom.setMessage(fmt.Sprintf("Error checking no_bypass permissions: %s", err_custom.Error()))
      return false, err_custom
    }
    return !result, nil
  }
  return false, &InvalidArgumentValueError{CustomError{fmt.Sprintf("The no_bypass value must be a boolean or a map. Current value: %v", no_bypass)}}
}

func (this *LogicalPermissions) checkBypassAccess(context map[string]interface{}) (bool, CustomErrorInterface) {
  bypass_callback := this.GetBypassCallback()
  if bypass_callback != nil {
    bypass_access, err_custom := bypass_callback(context)
    if err_custom != nil {
      return false, &CustomError{err_custom.Error()}
    }
    return bypass_access, nil
  }
  return false, nil
}

func (this *LogicalPermissions) dispatch(permissions interface{}, permtype string, context map[string]interface{}) (bool, CustomErrorInterface) {
  if bool_permissions, ok := permissions.(bool); ok {
    if bool_permissions == true {
      if permtype != "" {
        return false, &InvalidArgumentValueError{CustomError{fmt.Sprintf("You cannot put a boolean permission as a descendant to a permission type. Existing type: %s. Evaluated permissions: %v", permtype, bool_permissions)}}
      }
      return true, nil
    } else if bool_permissions == false {
      if permtype != "" {
        return false, &InvalidArgumentValueError{CustomError{fmt.Sprintf("You cannot put a boolean permission as a descendant to a permission type. Existing type: %s. Evaluated permissions: %v", permtype, bool_permissions)}}
      }
      return false, nil
    }
  }
  if str_permissions, ok := permissions.(string); ok {
    if str_permissions == "TRUE" {
      if permtype != "" {
        return false, &InvalidArgumentValueError{CustomError{fmt.Sprintf("You cannot put a boolean permission as a descendant to a permission type. Existing type: %s. Evaluated permissions: %v", permtype, str_permissions)}}
      }
      return true, nil
    } else if str_permissions == "FALSE" {
      if permtype != "" {
        return false, &InvalidArgumentValueError{CustomError{fmt.Sprintf("You cannot put a boolean permission as a descendant to a permission type. Existing type: %s. Evaluated permissions: %v", permtype, str_permissions)}}
      }
      return false, nil
    }

    access, err_custom := this.externalAccessCheck(str_permissions, permtype, context)
    if err_custom != nil {
      return false, err_custom
    }
    return access, nil
  }
  if slice_permissions, ok := permissions.([]interface{}); ok {
    if len(slice_permissions) > 0 {
      access, err_custom := this.processOR(slice_permissions, permtype, context)
      if err_custom != nil {
        return false, err_custom
      }
      return access, nil
    }
    return false, nil
  }
  if map_permissions, ok := permissions.(map[string]interface{}); ok {
    if len(map_permissions) == 1 {
      key := ""
      for k, _ := range map_permissions {
        key = k
        break
      }
      value := map_permissions[key]
      if key == "no_bypass" {
        return false, &InvalidArgumentValueError{CustomError{fmt.Sprintf("The no_bypass key must be placed highest in the permission hierarchy. Evaluated permissions: %v", map_permissions)}}
      }
      if key == "AND" {
        access, err_custom := this.processAND(value, permtype, context)
        if err_custom != nil {
          return false, err_custom
        }
        return access, nil
      }
      if key == "NAND" {
        access, err_custom := this.processNAND(value, permtype, context)
        if err_custom != nil {
          return false, err_custom
        }
        return access, nil
      }
      if key == "OR" {
        access, err_custom := this.processOR(value, permtype, context)
        if err_custom != nil {
          return false, err_custom
        }
        return access, nil
      }
      if key == "NOR" {
        access, err_custom := this.processNOR(value, permtype, context)
        if err_custom != nil {
          return false, err_custom
        }
        return access, nil
      }
      if key == "XOR" {
        access, err_custom := this.processXOR(value, permtype, context)
        if err_custom != nil {
          return false, err_custom
        }
        return access, nil
      }
      if key == "NOT" {
        access, err_custom := this.processNOT(value, permtype, context)
        if err_custom != nil {
          return false, err_custom
        }
        return access, nil
      }
      if key == "TRUE" || key == "FALSE" {
        return false, &InvalidArgumentValueError{CustomError{fmt.Sprintf("A boolean permission cannot have children. Evaluated permissions: %v", map_permissions)}}
      }
      if _, err := strconv.Atoi(key); err != nil {
        if permtype != "" {
          return false, &InvalidArgumentValueError{CustomError{fmt.Sprintf("You cannot put a permission type as a descendant to another permission type. Existing type: %s. Evaluated permissions: %v", permtype, map_permissions)}}
        }
        permtype = key
      }
      value_type := ""
      if _, ok := value.([]interface{}); ok {
        value_type = "slice"
      } else if _, ok := value.(map[string]interface{}); ok {
        value_type = "map"
      }
      if value_type == "slice" || value_type == "map" {
        access, err_custom := this.processOR(value, permtype, context)
        if err_custom != nil {
          return false, err_custom
        }
        return access, nil
      }

      access, err_custom := this.dispatch(value, permtype, context)
      if err_custom != nil {
        return false, err_custom
      }
      return access, nil

    }
    if len(map_permissions) > 1 {
      access, err_custom := this.processOR(map_permissions, permtype, context)
      if err_custom != nil {
        return false, err_custom
      }
      return access, nil
    }
    return false, nil
  }

  return false, &InvalidArgumentValueError{CustomError{fmt.Sprintf("A permission value must either be a boolean, a string, a slice or a map. Evaluated permissions: %v", permissions)}}
}

func (this *LogicalPermissions) processAND(permissions interface{}, permtype string, context map[string]interface{}) (bool, CustomErrorInterface) {
  if slice_permissions, ok := permissions.([]interface{}); ok {
    if len(slice_permissions) < 1 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value slice of an AND gate must contain a minimum of one element. Current value: %v", slice_permissions)}}
    }

    access := true
    for _, permission := range slice_permissions {
      result, err_custom := this.dispatch(permission, permtype, context)
      if err_custom != nil {
        return false, err_custom
      }
      access = access && result
      if !access {
        break
      }
    }
    return access, nil
  }
  if map_permissions, ok := permissions.(map[string]interface{}); ok {
    if len(map_permissions) < 1 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value map of an AND gate must contain a minimum of one element. Current value: %v", map_permissions)}}
    }

    access := true
    for k, v := range map_permissions {
      subpermissions := map[string]interface{}{k: v}
      result, err_custom := this.dispatch(subpermissions, permtype, context)
      if err_custom != nil {
        return false, err_custom
      }
      access = access && result
      if !access {
        break
      }
    }
    return access, nil
  }

  return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value of an AND gate must be a slice or map. Current value: %v", permissions)}}
}

func (this *LogicalPermissions) processNAND(permissions interface{}, permtype string, context map[string]interface{}) (bool, CustomErrorInterface) {
  if slice_permissions, ok := permissions.([]interface{}); ok {
    if len(slice_permissions) < 1 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value slice of a NAND gate must contain a minimum of one element. Current value: %v", slice_permissions)}}
    }
  } else if map_permissions, ok := permissions.(map[string]interface{}); ok {
    if len(map_permissions) < 1 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value map of a NAND gate must contain a minimum of one element. Current value: %v", map_permissions)}}
    }
  } else {
    return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value of a NAND gate must be a slice or map. Current value: %v", permissions)}}
  }

  result, err_custom := this.processAND(permissions, permtype, context)
  if err_custom != nil {
    return false, err_custom
  }
  access := !result
  return access, nil
}

func (this *LogicalPermissions) processOR(permissions interface{}, permtype string, context map[string]interface{}) (bool, CustomErrorInterface) {
  if slice_permissions, ok := permissions.([]interface{}); ok {
    if len(slice_permissions) < 1 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value slice of an OR gate must contain a minimum of one element. Current value: %v", slice_permissions)}}
    }

    access := false
    for _, permission := range slice_permissions {
      result, err_custom := this.dispatch(permission, permtype, context)
      if err_custom != nil {
        return false, err_custom
      }
      access = access || result
      if access {
        break
      }
    }
    return access, nil
  }
  if map_permissions, ok := permissions.(map[string]interface{}); ok {
    if len(map_permissions) < 1 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value map of an OR gate must contain a minimum of one element. Current value: %v", map_permissions)}}
    }

    access := false
    for k, v := range map_permissions {
      subpermissions := map[string]interface{}{k: v}
      result, err_custom := this.dispatch(subpermissions, permtype, context)
      if err_custom != nil {
        return false, err_custom
      }
      access = access || result
      if access {
        break
      }
    }
    return access, nil
  }

  return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value of an OR gate must be a slice or map. Current value: %v", permissions)}}
}

func (this *LogicalPermissions) processNOR(permissions interface{}, permtype string, context map[string]interface{}) (bool, CustomErrorInterface) {
  if slice_permissions, ok := permissions.([]interface{}); ok {
    if len(slice_permissions) < 1 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value slice of a NOR gate must contain a minimum of one element. Current value: %v", slice_permissions)}}
    }
  } else if map_permissions, ok := permissions.(map[string]interface{}); ok {
    if len(map_permissions) < 1 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value map of a NOR gate must contain a minimum of one element. Current value: %v", map_permissions)}}
    }
  } else {
    return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value of a NOR gate must be a slice or map. Current value: %v", permissions)}}
  }

  result, err_custom := this.processOR(permissions, permtype, context)
  if err_custom != nil {
    return false, err_custom
  }
  access := !result
  return access, nil
}

func (this *LogicalPermissions) processXOR(permissions interface{}, permtype string, context map[string]interface{}) (bool, CustomErrorInterface) {
  if slice_permissions, ok := permissions.([]interface{}); ok {
    if len(slice_permissions) < 2 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value slice of an XOR gate must contain a minimum of two elements. Current value: %v", slice_permissions)}}
    }

    access := false
    count_true := 0
    count_false := 0
    for _, permission := range slice_permissions {
      result, err_custom := this.dispatch(permission, permtype, context)
      if err_custom != nil {
        return false, err_custom
      }
      if result {
        count_true++
      } else {
        count_false++
      }
      if count_true > 0 && count_false > 0 {
        access = true
        break
      }
    }
    return access, nil
  }
  if map_permissions, ok := permissions.(map[string]interface{}); ok {
    if len(map_permissions) < 2 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value map of an XOR gate must contain a minimum of two elements. Current value: %v", map_permissions)}}
    }

    access := false
    count_true := 0
    count_false := 0
    for k, v := range map_permissions {
      subpermissions := map[string]interface{}{k: v}
      result, err_custom := this.dispatch(subpermissions, permtype, context)
      if err_custom != nil {
        return false, err_custom
      }
      if result {
        count_true++
      } else {
        count_false++
      }
      if count_true > 0 && count_false > 0 {
        access = true
        break
      }
    }
    return access, nil
  }

  return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value of an XOR gate must be a slice or map. Current value: %v", permissions)}}
}

func (this *LogicalPermissions) processNOT(permissions interface{}, permtype string, context map[string]interface{}) (bool, CustomErrorInterface) {
  if map_permissions, ok := permissions.(map[string]interface{}); ok {
    if len(map_permissions) != 1 {
      return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("A NOT permission must have exactly one child in the value map. Current value: %v", map_permissions)}}
    }
  } else if str_permissions, ok := permissions.(string); ok {
    if str_permissions == "" {
      return false, &InvalidValueForLogicGateError{CustomError{"A NOT permission cannot have an empty string as its value."}}
    }
  } else {
    return false, &InvalidValueForLogicGateError{CustomError{fmt.Sprintf("The value of a NOT gate must be a map or string. Current value: %v", permissions)}}
  }

  result, err_custom := this.dispatch(permissions, permtype, context)
  if err_custom != nil {
    return false, err_custom
  }
  access := !result
  return access, nil
}

func (this *LogicalPermissions) externalAccessCheck(permission string, permtype string, context map[string]interface{}) (bool, CustomErrorInterface) {
  exists, err_custom := this.TypeExists(permtype)
  if err_custom != nil {
    return false, &CustomError{err_custom.Error()}
  }
  if !exists {
    return false, &PermissionTypeNotRegisteredError{CustomError{fmt.Sprintf("The permission type \"%s\" has not been registered. Please use LogicalPermissions::AddType() or LogicalPermissions::SetTypes() to register permission types.", permtype)}}
  }

  callback, err_custom := this.GetTypeCallback(permtype)
  if err_custom != nil {
    return false, &CustomError{err_custom.Error()}
  }

  access, err_custom := callback(permission, context)
  if err_custom != nil {
    return false, &CustomError{err_custom.Error()}
  }

  return access, nil
}