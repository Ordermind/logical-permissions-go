package logicalpermissions_test

import (
  "fmt"
  "testing"
  "github.com/stretchr/testify/assert"
  . "github.com/ordermind/logical-permissions-go"
)

func TestCreation(t *testing.T) {
  t.Parallel()
  lp := LogicalPermissions{}
  var i interface{} = &lp
  _, ok := i.(LogicalPermissionsInterface)
  assert.True(t, ok, "LogicalPermissions is not implementing LogicalPermissionsInterface correctly.")
}

/*-----------LogicalPermissions::AddType()-------------*/

func TestAddTypeParamNameEmpty(t *testing.T) {
  t.Parallel()
  lp := LogicalPermissions{}
  type_callback := func(string, map[string]interface{}) bool {return true}
  err := lp.AddType("", type_callback)
  if assert.Error(t, err) {
     assert.IsType(t, &InvalidArgumentValueError{}, err)
  }
}

func TestAddType(t *testing.T) {
  t.Parallel()
  lp := LogicalPermissions{}
  type_callback := func(string, map[string]interface{}) bool {return true}
  err := lp.AddType("test", type_callback)
  if err != nil {
    t.Error(fmt.Sprintf("LogicalPermissions::AddType() returned an error: %s", err))
  }
  exists, err2 := lp.TypeExists("test")
  if err2 != nil {
    t.Error(fmt.Sprintf("LogicalPermissions::TypeExists() returned an error: %s", err2))
  }
  assert.True(t, exists)
}

/*-----------LogicalPermissions::RemoveType()-------------*/

func TestRemoveTypeParamNameEmpty(t *testing.T) {
  t.Parallel()
  lp := LogicalPermissions{}
  err := lp.RemoveType("")
  if assert.Error(t, err) {
    assert.IsType(t, &InvalidArgumentValueError{}, err)
  }
}

func TestRemoveTypeUnregisteredType(t *testing.T) {
  t.Parallel()
  lp := LogicalPermissions{}
  err := lp.RemoveType("test")
  if assert.Error(t, err) {
    assert.IsType(t, &PermissionTypeNotRegisteredError{}, err)
  }
}

func TestRemoveType(t *testing.T) {
  t.Parallel()
  lp := LogicalPermissions{}
  type_callback := func(string, map[string]interface{}) bool {return true}
  err := lp.AddType("test", type_callback)
  if err != nil {
    t.Error(fmt.Sprintf("LogicalPermissions::AddType() returned an error: %s", err))
  }
  err2 := lp.RemoveType("test")
  if err2 != nil {
    t.Error(fmt.Sprintf("LogicalPermissions::RemoveType() returned an error: %s", err2))
  }
  exists, err3 := lp.TypeExists("test")
  if err3 != nil {
    t.Error(fmt.Sprintf("LogicalPermissions::TypeExists() returned an error: %s", err3))
  }
  assert.False(t, exists)
}

/*-------------LogicalPermissions::TypeExists()--------------*/

func TestTypeExistsParamNameEmpty(t *testing.T) {
  t.Parallel()
  lp := LogicalPermissions{}
  _, err := lp.TypeExists("")
  if assert.Error(t, err) {
    assert.IsType(t, &InvalidArgumentValueError{}, err)
  }
}

func TestTypeExists(t *testing.T) {
  t.Parallel()
  lp := LogicalPermissions{}
  type_callback := func(string, map[string]interface{}) bool {return true}
  err := lp.AddType("test", type_callback)
  if err != nil {
    t.Error(fmt.Sprintf("LogicalPermissions::AddType() returned an error: %s", err))
  }
  exists, err2 := lp.TypeExists("test")
  if err2 != nil {
    t.Error(fmt.Sprintf("LogicalPermissions::TypeExists() returned an error: %s", err2))
  }
  assert.True(t, exists)
}

/*-------------LogicalPermissions::GetTypeCallback()--------------*/

func TestGetTypeCallbackParamNameEmpty(t *testing.T) {
  t.Parallel()
  lp := LogicalPermissions{}
  _, err := lp.GetTypeCallback("")
  if assert.Error(t, err) {
    assert.IsType(t, &InvalidArgumentValueError{}, err)
  }
}

func TestGetTypeCallbackUnregisteredType(t *testing.T) {
  t.Parallel()
  lp := LogicalPermissions{}
  _, err := lp.GetTypeCallback("test")
  if assert.Error(t, err) {
    assert.IsType(t, &PermissionTypeNotRegisteredError{}, err)
  }
}

func TestGetTypeCallback(t *testing.T) {
  t.Parallel()
  lp := LogicalPermissions{}
  callback1 := func(string, map[string]interface{}) bool {
    return true
  }
  err := lp.AddType("test", callback1)
  if err != nil {
    t.Error(fmt.Sprintf("LogicalPermissions::AddType() returned an error: %s", err))
  }
  callback2, err2 := lp.GetTypeCallback("test")
  if err2 != nil {
    t.Error(fmt.Sprintf("LogicalPermissions::GetTypeCallback() returned an error: %s", err2))
  }
  assert.True(t, callback2("test", make(map[string]interface{})))
}

