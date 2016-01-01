package logicalpermissions_test

import (
  //"fmt"
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
  err := lp.AddType("", func(string, map[string]interface{}) bool {return true})
  if assert.Error(t, err) {
     assert.IsType(t, &InvalidArgumentValueError{}, err)
  }
}

func TestAddType(t *testing.T) {
  t.Parallel()
  lp := LogicalPermissions{}
  err := lp.AddType("test", func(string, map[string]interface{}) bool {return true})
  if assert.NoError(t, err) {
    assert.True(t, lp.TypeExists("test"))
  }
}