package core

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
)

type method struct {
	value      reflect.Value
	methodType reflect.Type
	argsNum    int
}

func (mtd *method) call(args any) (any, error) {
	if args == nil {
		args = make([]any, 0)
	}

	argsType := reflect.TypeOf(args)

	switch argsType.Kind() {
	case reflect.Slice, reflect.Array:
	default:
		args = []any{args}
	}
	argList := reflect.ValueOf(args)
	if mtd.argsNum != argList.Len() {
		return nil, errors.New(fmt.Sprintf("参数数量错误：当前方法需要%d个参数，实际传入%d个参数", mtd.argsNum, argList.Len()))
	}
	argValues := make([]reflect.Value, 0, mtd.argsNum)
	for i := 0; i < mtd.argsNum; i++ {
		inType := mtd.methodType.In(i)
		argValue := argList.Index(i)
		if argValue.Kind() == reflect.Interface {
			if !argValue.IsNil() {
				argValue = argValue.Elem()
			}
		}
		if inType.Kind() == reflect.Interface {
			argValues = append(argValues, argValue)
			continue
		}
		argType := argValue.Type()
		if inType != argType {
			return nil, errors.New(fmt.Sprintf("参数类型错误：参数[%d]的类型应该为%s，实际类型为%s", i, inType, argType))
		}
		argValues = append(argValues, argValue)
	}

	values := mtd.value.Call(argValues)
	returns := len(values)
	if returns == 0 {
		return nil, nil
	}
	if returns == 1 {
		return values[0].Interface(), nil
	}
	if values[1].Interface() != nil {
		return values[0], values[1].Interface().(error)
	}
	return values[0].Interface(), nil
}

type Registry struct {
	methods        map[string]*method
	patch          map[string]*method
	patchCount     int
	patchMutex     sync.RWMutex
	afterHooks     map[string][]func()
	afterHookMutex sync.RWMutex
}

func (r *Registry) RegisterMethods(item interface{}) {

	if r.methods == nil {
		if r.methods == nil {
			r.methods = make(map[string]*method)
		}
	}

	pv := reflect.ValueOf(item)
	pt := reflect.TypeOf(item)
	v := pv.Elem()
	t := v.Type()
	typeName := t.Name()
	for i := 0; i < pv.NumMethod(); i++ {
		key := SnakeCase(fmt.Sprintf(`%s/%s`, typeName, pt.Method(i).Name))

		m := pv.Method(i)
		mt := m.Type()

		r.methods[key] = &method{
			value:      m,
			methodType: mt,
			argsNum:    mt.NumIn(),
		}
	}
}

func (r *Registry) Patch(module, action string, f any) {
	r.patchMutex.Lock()
	defer r.patchMutex.Unlock()
	pv := reflect.Indirect(reflect.ValueOf(f))
	pt := pv.Type()

	if pt.Kind() != reflect.Func {
		panic("*Registry.Patch() parameter f must a function")
	}

	if r.patch == nil {
		r.patch = make(map[string]*method)
	}

	key := SnakeCase(fmt.Sprintf(`%s/%s`, module, action))
	r.patch[key] = &method{
		value:      pv,
		methodType: pt,
		argsNum:    pt.NumIn(),
	}
	r.patchCount++
}

func (r *Registry) Unpatch(module, action string) {
	r.patchMutex.Lock()
	defer r.patchMutex.Unlock()

	if r.patch == nil {
		return
	}

	key := SnakeCase(fmt.Sprintf(`%s/%s`, module, action))
	delete(r.patch, key)
	r.patchCount--
}

func (r *Registry) UnpatchAll() {
	r.patchMutex.Lock()
	defer r.patchMutex.Unlock()

	r.patch = make(map[string]*method)
}

func (r *Registry) After(module, action string, f func()) {
	r.afterHookMutex.Lock()
	defer r.afterHookMutex.Unlock()

	if r.afterHooks == nil {
		r.afterHooks = make(map[string][]func())
	}

	key := SnakeCase(fmt.Sprintf(`%s/%s`, module, action))

	if _, ok := r.afterHooks[key]; !ok {
		r.afterHooks[key] = make([]func(), 0, 16)
	}

	r.afterHooks[key] = append(r.afterHooks[key], f)
}

func (r *Registry) callAfter(key string) {
	r.afterHookMutex.RLock()
	defer r.afterHookMutex.RUnlock()

	funs, ok := r.afterHooks[key]

	if !ok {
		return
	}

	for _, f := range funs {
		f()
	}
}

func (r *Registry) Call(typeName, methodName string, args interface{}) (interface{}, error) {
	var (
		mtd *method
		ok  bool
	)

	key := SnakeCase(fmt.Sprintf(`%s/%s`, typeName, methodName))

	if r.patchCount > 0 {
		r.patchMutex.RLock()
		mtd, ok = r.patch[key]
		r.patchMutex.RUnlock()
	}
	if !ok {
		mtd, ok = r.methods[key]
	}

	if !ok {
		return nil, errors.New(fmt.Sprintf("api不存在：%s", key))
	}
	defer r.callAfter(key)
	return mtd.call(args)
}

func (r *Registry) Has(typeName, methodName string) (ok bool) {
	key := SnakeCase(fmt.Sprintf(`%s/%s`, typeName, methodName))
	if r.patchCount > 0 {
		r.patchMutex.RLock()
		_, ok = r.patch[key]
		r.patchMutex.RUnlock()
	}
	if !ok {
		_, ok = r.methods[key]
	}

	return ok
}
