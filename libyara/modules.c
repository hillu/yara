/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <yara/exec.h>
#include <yara/libyara.h>
#include <yara/modules.h>
#include <yara/strutils.h>

#if defined(HAVE_DLFCN_H)
#include <dlfcn.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

#define MODULE(name) extern YR_MODULE name##__module;

#include <modules/module_list>

#undef MODULE

YR_MODULE** yr_modules_table = NULL;
int yr_modules_count = 0;

YR_API int yr_modules_add(YR_MODULE* module)
{
  int result = module->initialize(module);
  if (result != ERROR_SUCCESS)
    return result;

  yr_modules_count++;
  yr_modules_table = realloc(
      yr_modules_table, yr_modules_count * sizeof(YR_MODULE*));
  yr_modules_table[yr_modules_count - 1] = module;

  return ERROR_SUCCESS;
}

#if defined(_WIN32)
#define SO_SUFFIX ".dll"
#elif defined(__APPLE__) && defined(__MACH__)
#define SO_SUFFIX ".dylib"
#else
#define SO_SUFFIX ".so"
#endif

#if defined(HAVE_DLFCN_H) || defined(_WIN32)
YR_API int yr_modules_add_plugin(char* name)
{
  int result;
  char* dlopen_path;
  char* alt_dlopen_path = NULL;

  bool has_dot = strchr(name, '.');
  bool has_path = strchr(name, '/') || strchr(name, '\\');
  
#if defined(HAVE_DLFCN_H)
  void* h;
#elif defined(_WIN32)
  HANDLE h;
#endif
  
  if (has_dot) {
    dlopen_path = strdup(name);
  } else {
    yr_asprintf(&dlopen_path, "%s" SO_SUFFIX, name);
  }

  if (!has_path && !has_dot) {
    if (!strncmp(name, "yara-", 5))
      yr_asprintf(&alt_dlopen_path, "%s" SO_SUFFIX, name+5);
    else
      yr_asprintf(&alt_dlopen_path, "yara-%s" SO_SUFFIX, name);
  }
                   
  YR_PLUGIN_MODULE_FUNC f;
#if defined(HAVE_DLFCN_H)
  h = dlopen(name, 0);
  if (h == NULL && alt_dlopen_path)
    h = dlopen(alt_dlopen_path, 0);
  if (h == NULL) {
      result = ERROR_COULD_NOT_OPEN_FILE;
      goto out;
  }
  f = dlsym(h, "yara_module");
#elif defined(_WIN32)
  h = LoadLibraryA(dlopen_path);
  if (h == NULL && alt_dlopen_path)
    h = LoadLibraryA(alt_dlopen_path);
  if (h == NULL) {
      result = ERROR_COULD_NOT_OPEN_FILE;
      goto out;
  }
  f = GetProcAddress(h, "yara_module");
#endif
  if (f == NULL) {
    result = ERROR_COULD_NOT_OPEN_FILE;
    goto out;
  }
  result = yr_modules_add(f());

 out:
  if (dlopen_path)
    free(alt_dlopen_path);
  if (alt_dlopen_path)
    free(alt_dlopen_path);

  return result;
}

#else
YR_API int yr_modules_add_plugin(char* name)
{
  return ERROR_COULD_NOT_READ_FILE;
}
#endif

#define foreach_modules(module) \
  for (int i = 0; i < yr_modules_count && (module = yr_modules_table[i]); i++)

int yr_modules_initialize()
{
  int result;

#define MODULE(name)                        \
  result = yr_modules_add(&name##__module); \
  if (result != ERROR_SUCCESS)              \
    return result;

#include <modules/module_list>

#undef MODULE

  return ERROR_SUCCESS;
}

int yr_modules_finalize()
{
  YR_MODULE* module;
  foreach_modules(module)
  {
    int result = module->finalize(module);

    if (result != ERROR_SUCCESS)
      return result;
  }

  return ERROR_SUCCESS;
}

int yr_modules_do_declarations(
    const char* module_name,
    YR_OBJECT* main_structure)
{
  YR_MODULE* module;
  foreach_modules(module)
  {
    if (strcmp(module->name, module_name) == 0)
      return module->declarations(main_structure);
  }

  return ERROR_UNKNOWN_MODULE;
}

int yr_modules_load(const char* module_name, YR_SCAN_CONTEXT* context)
{
  int result;

  YR_MODULE* module;
  YR_MODULE_IMPORT mi;

  YR_OBJECT* module_structure = (YR_OBJECT*) yr_hash_table_lookup(
      context->objects_table, module_name, NULL);

  // if module_structure != NULL, the module was already
  // loaded, return successfully without doing nothing.

  if (module_structure != NULL)
    return ERROR_SUCCESS;

  // not loaded yet

  FAIL_ON_ERROR(yr_object_create(
      OBJECT_TYPE_STRUCTURE, module_name, NULL, &module_structure));

  // initialize canary for module's top-level structure, every other object
  // within the module inherits the same canary.
  yr_object_set_canary(module_structure, context->canary);

  mi.module_name = module_name;
  mi.module_data = NULL;
  mi.module_data_size = 0;

  result = context->callback(
      context, CALLBACK_MSG_IMPORT_MODULE, &mi, context->user_data);

  if (result == CALLBACK_ERROR)
  {
    yr_object_destroy(module_structure);
    return ERROR_CALLBACK_ERROR;
  }

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_modules_do_declarations(module_name, module_structure),
      yr_object_destroy(module_structure));

  FAIL_ON_ERROR_WITH_CLEANUP(
      yr_hash_table_add(
          context->objects_table, module_name, NULL, module_structure),
      yr_object_destroy(module_structure));

  foreach_modules(module)
  {
    if (strcmp(module->name, module_name) == 0)
    {
      result = module->load(
          context, module_structure, mi.module_data, mi.module_data_size);

      if (result != ERROR_SUCCESS)
        return result;
    }
  }

  result = context->callback(
      context,
      CALLBACK_MSG_MODULE_IMPORTED,
      module_structure,
      context->user_data);

  if (result == CALLBACK_ERROR)
    return ERROR_CALLBACK_ERROR;

  return ERROR_SUCCESS;
}

int yr_modules_unload_all(YR_SCAN_CONTEXT* context)
{
  YR_MODULE* module;

  foreach_modules(module)
  {
    YR_OBJECT* module_structure = (YR_OBJECT*) yr_hash_table_remove(
        context->objects_table, module->name, NULL);

    if (module_structure != NULL)
    {
      module->unload(module_structure);
      yr_object_destroy(module_structure);
    }
  }

  return ERROR_SUCCESS;
}
