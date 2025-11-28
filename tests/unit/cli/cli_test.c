#include "../../../lib/cli/cli.h"
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const cli_flag_meta_t EXAMPLE_BOOL_FLAG = {
    .short_name = "b",
    .long_name = "bool-flag",
    .description = "A boolean flag",
    .env_variable = "BOOL_FLAG",
    .type = FLAG_TYPE_BOOL,
    .default_value = {.bool_value = false},
};

static const cli_flag_meta_t EXAMPLE_STRING_FLAG = {
    .short_name = "s",
    .long_name = "string-flag",
    .description = "A string flag",
    .env_variable = "STRING_FLAG",
    .type = FLAG_TYPE_STRING,
    .default_value = {.string_value = "default"},
};

static const cli_flag_meta_t EXAMPLE_STRINGS_FLAG = {
    .short_name = "m",
    .long_name = "strings-flag",
    .description = "A multiple strings flag",
    .env_variable = "MULTIPLE_STRINGS_FLAG",
    .type = FLAG_TYPE_STRINGS,
    .default_value = {
        .strings_value = {.list = (const char *[]){"one", "two", "three"},
                          .count = 3}}};

static const cli_app_meta_t EXAMPLE_APP = {.name = "testapp",
                                           .version = "1.0.0",
                                           .description =
                                               "A test CLI application",
                                           .usage = "[options]",
                                           .examples = "testapp --help"};

static void assert_string_equal(const char *expected, const char *actual) {
  if (expected == NULL && actual == NULL) {
    return; // both NULL — consider equal
  }

  if (expected == NULL || actual == NULL) {
    fprintf(stderr,
            "String mismatch:\n"
            "  expected: \"%s\"\n"
            "  actual:   \"%s\"\n",
            expected ? expected : "(null)", actual ? actual : "(null)");
    abort();
  }

  if (strcmp(expected, actual) != 0) {
    fprintf(stderr,
            "String mismatch:\n"
            "  expected: \"%s\"\n"
            "  actual:   \"%s\"\n",
            expected, actual);

    size_t i = 0;
    while (expected[i] && actual[i] && expected[i] == actual[i]) {
      i++;
    }

    fprintf(stderr, "  first difference at index %zu\n", i);
    abort();
  }
}

static void test_cli_app_add_flag() {
  cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);
  assert(app != NULL);

  const cli_flag_state_t *bool_flag = cli_app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  assert(bool_flag != NULL);

  const cli_flag_state_t *string_flag = cli_app_add_flag(app, &EXAMPLE_STRING_FLAG);
  assert(string_flag != NULL);

  const cli_flag_state_t *strings_flag =
      cli_app_add_flag(app, &EXAMPLE_STRINGS_FLAG);
  assert(strings_flag != NULL);

  assert(app->flags.count == 3);

  assert(bool_flag->meta->type == FLAG_TYPE_BOOL);
  assert(string_flag->meta->type == FLAG_TYPE_STRING);
  assert(strings_flag->meta->type == FLAG_TYPE_STRINGS);

  assert(bool_flag->value.bool_value == false);

  assert_string_equal("default", string_flag->value.string_value);

  assert(strings_flag->value.strings_value.count == 3);
  assert_string_equal("one", strings_flag->value.strings_value.list[0]);
  assert_string_equal("two", strings_flag->value.strings_value.list[1]);
  assert_string_equal("three", strings_flag->value.strings_value.list[2]);

  free_cli_app(app);
}

static void test_help_nothing() {
  cli_app_state_t *app = new_cli_app(&(cli_app_meta_t){0});

  char *help = cli_app_help(app);
  assert_string_equal("app", help);

  free(help);
  free_cli_app(app);
}

static void test_help_bool_flag_only() {
  cli_app_state_t *app = new_cli_app(&(cli_app_meta_t){0});

  cli_app_add_flag(app, &EXAMPLE_BOOL_FLAG);

  char *help = cli_app_help(app);
  assert_string_equal("app\n\n"
                      "Options:\n"
                      "  -b, --bool-flag  A boolean flag [$BOOL_FLAG]",
                      help);

  free(help);
  free_cli_app(app);
}

static void test_help_bool_and_string_flags() {
  cli_app_state_t *app = new_cli_app(&(cli_app_meta_t){0});

  cli_app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  cli_app_add_flag(app, &EXAMPLE_STRING_FLAG);

  char *help = cli_app_help(app);
  assert_string_equal("app\n\n"
                      "Options:\n"
                      "  -b, --bool-flag    A boolean flag [$BOOL_FLAG]\n"
                      "  -s, --string-flag  A string flag (default: "
                      "\"default\") [$STRING_FLAG]",
                      help);

  free(help);
  free_cli_app(app);
}

static void test_help_bool_string_and_strings_flags() {
  cli_app_state_t *app = new_cli_app(&(cli_app_meta_t){0});

  cli_app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  cli_app_add_flag(app, &EXAMPLE_STRING_FLAG);
  cli_app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

  char *help = cli_app_help(app);
  assert_string_equal(
      "app\n\n"
      "Options:\n"
      "  -b, --bool-flag     A boolean flag [$BOOL_FLAG]\n"
      "  -s, --string-flag   A string flag (default: "
      "\"default\") [$STRING_FLAG]\n"
      "  -m, --strings-flag  A multiple strings flag (default: [\"one\", "
      "\"two\", \"three\"]) [$MULTIPLE_STRINGS_FLAG]",
      help);

  free(help);
  free_cli_app(app);
}

static void test_help_with_custom_flags() {
  cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

  cli_app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  cli_app_add_flag(app, &EXAMPLE_STRING_FLAG);
  cli_app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

  cli_app_add_flag(app, &(cli_flag_meta_t){
                            .short_name = "x",
                            .description = "Short only flag",
                            .type = FLAG_TYPE_BOOL,
                        });
  cli_app_add_flag(app, &(cli_flag_meta_t){
                            .long_name = "xxx",
                            .description = "Long only flag",
                            .type = FLAG_TYPE_BOOL,
                        });

  char *help = cli_app_help(app);

  assert_string_equal(
      "testapp 1.0.0\n\n"
      "A test CLI application\n\n"
      "Usage: testapp [options]\n\n"
      "Options:\n"
      "  -b, --bool-flag     A boolean flag [$BOOL_FLAG]\n"
      "  -s, --string-flag   A string flag (default: \"default\") "
      "[$STRING_FLAG]\n"
      "  -m, --strings-flag  A multiple strings flag (default: [\"one\", "
      "\"two\", \"three\"]) [$MULTIPLE_STRINGS_FLAG]\n"
      "  -x                  Short only flag\n"
      "      --xxx           Long only flag\n\n"
      "Examples:\n"
      "testapp --help",
      help);

  free(help);
  free_cli_app(app);
}

static void test_cli_app_parse_args_common() {
  cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

  const cli_flag_state_t *bool_flag = cli_app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  const cli_flag_state_t *string_flag = cli_app_add_flag(app, &EXAMPLE_STRING_FLAG);
  const cli_flag_state_t *strings_flag =
      cli_app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

  const char *argv[] = {
      "--bool-flag",    // bool flag
      "-s",             // string flag
      "custom_value",   // string flag value
      "--strings-flag", // strings flag
      "first",          // strings flag value 1
      "-m",             // strings flag again
      "second",         // strings flag value 2
      "positional1",    // arg 1
      "positional2",    // arg 2
  };

  cli_args_parsing_result_t *res =
      cli_app_parse_args(app, argv, sizeof(argv) / sizeof(argv[0]));

  assert(res->code == FLAGS_PARSING_OK);
  assert(res->message == NULL);

  free_cli_args_parsing_result(res);

  assert(bool_flag->value.bool_value == true);
  assert(bool_flag->value_source == FLAG_VALUE_SOURCE_CLI);

  assert_string_equal("custom_value", string_flag->value.string_value);
  assert(string_flag->value_source == FLAG_VALUE_SOURCE_CLI);

  assert(strings_flag->value.strings_value.count == 2);
  assert_string_equal("first", strings_flag->value.strings_value.list[0]);
  assert_string_equal("second", strings_flag->value.strings_value.list[1]);
  assert(strings_flag->value_source == FLAG_VALUE_SOURCE_CLI);

  assert(app->args.count == 2);
  assert_string_equal("positional1", app->args.list[0]);
  assert_string_equal("positional2", app->args.list[1]);

  free_cli_app(app);
}

static void test_cli_app_parse_args_flags_with_equals_sign_long_form() {
  cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

  const cli_flag_state_t *bool_flag = cli_app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  const cli_flag_state_t *string_flag = cli_app_add_flag(app, &EXAMPLE_STRING_FLAG);
  const cli_flag_state_t *strings_flag =
      cli_app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

  const char *argv[] = {
      "--bool-flag=yes",            // bool flag
      "--string-flag=custom value", // string flag with value
      "--strings-flag=first",       // strings flag with value 1
      "--strings-flag=second",      // strings flag with value 2
      "positional1",                // arg 1
      "positional2",                // arg 2
  };

  cli_args_parsing_result_t *res =
      cli_app_parse_args(app, argv, sizeof(argv) / sizeof(argv[0]));

  assert(res->code == FLAGS_PARSING_OK);
  assert(res->message == NULL);

  free_cli_args_parsing_result(res);

  assert(bool_flag->value.bool_value == true);
  assert(bool_flag->value_source == FLAG_VALUE_SOURCE_CLI);

  assert_string_equal("custom value", string_flag->value.string_value);
  assert(string_flag->value_source == FLAG_VALUE_SOURCE_CLI);

  assert(strings_flag->value.strings_value.count == 2);
  assert_string_equal("first", strings_flag->value.strings_value.list[0]);
  assert_string_equal("second", strings_flag->value.strings_value.list[1]);
  assert(strings_flag->value_source == FLAG_VALUE_SOURCE_CLI);

  assert(app->args.count == 2);
  assert_string_equal("positional1", app->args.list[0]);
  assert_string_equal("positional2", app->args.list[1]);

  free_cli_app(app);
}

static void test_cli_app_parse_args_flags_with_equals_sign_short_form() {
  cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

  const cli_flag_state_t *bool_flag = cli_app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  const cli_flag_state_t *string_flag = cli_app_add_flag(app, &EXAMPLE_STRING_FLAG);
  const cli_flag_state_t *strings_flag =
      cli_app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

  const char *argv[] = {
      "-b=No",          // bool flag
      "-s=custom value", // string flag with value
      "-m=first",        // strings flag with value 1
      "-m=second",       // strings flag with value 2
      "positional1",     // arg 1
      "positional2",     // arg 2
  };

  cli_args_parsing_result_t *res =
      cli_app_parse_args(app, argv, sizeof(argv) / sizeof(argv[0]));

  assert(res->code == FLAGS_PARSING_OK);
  assert(res->message == NULL);

  free_cli_args_parsing_result(res);

  assert(bool_flag->value.bool_value == false);
  assert(bool_flag->value_source == FLAG_VALUE_SOURCE_CLI);

  assert_string_equal("custom value", string_flag->value.string_value);
  assert(string_flag->value_source == FLAG_VALUE_SOURCE_CLI);

  assert(strings_flag->value.strings_value.count == 2);
  assert_string_equal("first", strings_flag->value.strings_value.list[0]);
  assert_string_equal("second", strings_flag->value.strings_value.list[1]);
  assert(strings_flag->value_source == FLAG_VALUE_SOURCE_CLI);

  assert(app->args.count == 2);
  assert_string_equal("positional1", app->args.list[0]);
  assert_string_equal("positional2", app->args.list[1]);

  free_cli_app(app);
}

static void test_cli_app_parse_args_defaults() {
  cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

  const cli_flag_state_t *bool_flag = cli_app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  const cli_flag_state_t *string_flag = cli_app_add_flag(app, &EXAMPLE_STRING_FLAG);
  const cli_flag_state_t *strings_flag =
      cli_app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

  const char *argv[] = {"foo"};

  cli_args_parsing_result_t *res =
      cli_app_parse_args(app, argv, sizeof(argv) / sizeof(argv[0]));

  assert(res->code == FLAGS_PARSING_OK);
  assert(res->message == NULL);

  free_cli_args_parsing_result(res);

  assert(bool_flag->value.bool_value == false);
  assert(bool_flag->value_source == FLAG_VALUE_SOURCE_DEFAULT);

  assert_string_equal("default", string_flag->value.string_value);
  assert(string_flag->value_source == FLAG_VALUE_SOURCE_DEFAULT);

  assert(strings_flag->value.strings_value.count == 3);
  assert_string_equal("one", strings_flag->value.strings_value.list[0]);
  assert_string_equal("two", strings_flag->value.strings_value.list[1]);
  assert_string_equal("three", strings_flag->value.strings_value.list[2]);
  assert(strings_flag->value_source == FLAG_VALUE_SOURCE_DEFAULT);

  assert(app->args.count == 1);
  assert_string_equal(app->args.list[0], "foo");

  free_cli_app(app);
}

static void test_cli_app_parse_args_empty() {
  cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

  const cli_flag_state_t *bool_flag = cli_app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  const cli_flag_state_t *string_flag = cli_app_add_flag(app, &EXAMPLE_STRING_FLAG);
  const cli_flag_state_t *strings_flag =
      cli_app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

  const char *argv[] = {NULL};

  cli_args_parsing_result_t *res = cli_app_parse_args(app, argv, 0);

  assert(res->code == FLAGS_PARSING_OK);
  assert(res->message == NULL);

  free_cli_args_parsing_result(res);

  assert(bool_flag->value.bool_value == false);
  assert(bool_flag->value_source == FLAG_VALUE_SOURCE_DEFAULT);

  assert_string_equal("default", string_flag->value.string_value);
  assert(string_flag->value_source == FLAG_VALUE_SOURCE_DEFAULT);

  assert(strings_flag->value.strings_value.count == 3);
  assert_string_equal("one", strings_flag->value.strings_value.list[0]);
  assert_string_equal("two", strings_flag->value.strings_value.list[1]);
  assert_string_equal("three", strings_flag->value.strings_value.list[2]);
  assert(strings_flag->value_source == FLAG_VALUE_SOURCE_DEFAULT);

  assert(app->args.count == 0);
  assert(app->args.list == NULL);

  free_cli_app(app);
}

static void test_cli_app_parse_args_env_vars() {
  cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

  const cli_flag_state_t *bool_flag = cli_app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  const cli_flag_state_t *string_flag = cli_app_add_flag(app, &EXAMPLE_STRING_FLAG);
  const cli_flag_state_t *strings_flag =
      cli_app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

  // set environment values
  setenv(EXAMPLE_BOOL_FLAG.env_variable, "true", 1);
  setenv(EXAMPLE_STRING_FLAG.env_variable, "env_value", 1);
  setenv(EXAMPLE_STRINGS_FLAG.env_variable, "env1,env2", 1);

  const char *argv[] = {NULL};

  cli_args_parsing_result_t *res = cli_app_parse_args(app, argv, 0);

  assert(res->code == FLAGS_PARSING_OK);
  assert(res->message == NULL);

  free_cli_args_parsing_result(res);

  assert(bool_flag->value.bool_value == true);
  assert(bool_flag->value_source == FLAG_VALUE_SOURCE_ENV);

  assert_string_equal("env_value", string_flag->value.string_value);
  assert(string_flag->value_source == FLAG_VALUE_SOURCE_ENV);

  // NOT supported for FLAG_TYPE_STRINGS, should use default value
  assert(strings_flag->value.strings_value.count == 3);
  assert_string_equal("one", strings_flag->value.strings_value.list[0]);
  assert_string_equal("two", strings_flag->value.strings_value.list[1]);
  assert_string_equal("three", strings_flag->value.strings_value.list[2]);
  assert(strings_flag->value_source == FLAG_VALUE_SOURCE_DEFAULT);

  // unset environment variables after parsing
  unsetenv(EXAMPLE_BOOL_FLAG.env_variable);
  unsetenv(EXAMPLE_STRING_FLAG.env_variable);
  unsetenv(EXAMPLE_STRINGS_FLAG.env_variable);

  free_cli_app(app);
}

static void test_cli_app_parse_args_double_run() {
  cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

  cli_flag_state_t *bool_flag = cli_app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  cli_flag_state_t *string_flag = cli_app_add_flag(app, &EXAMPLE_STRING_FLAG);

  // set environment values
  setenv("FOO_1", "true", 1);
  setenv("FOO_2", "env_value", 1);

  const char *argv[] = {NULL};

  { // first run - should not pick up env vars yet
    cli_args_parsing_result_t *res = cli_app_parse_args(app, argv, 0);

    assert(res->code == FLAGS_PARSING_OK);
    assert(res->message == NULL);

    free_cli_args_parsing_result(res);

    assert(bool_flag->value.bool_value == false);
    assert(bool_flag->value_source == FLAG_VALUE_SOURCE_DEFAULT);

    assert_string_equal("default", string_flag->value.string_value);
    assert(string_flag->value_source == FLAG_VALUE_SOURCE_DEFAULT);
  }

  { // second run - after changing env_variable names
    bool_flag->env_variable = strdup("FOO_1");   // <-- change env variable name
    string_flag->env_variable = strdup("FOO_2"); // <-- change env variable name

    cli_args_parsing_result_t *res = cli_app_parse_args(app, argv, 0);

    assert(res->code == FLAGS_PARSING_OK);
    assert(res->message == NULL);

    free_cli_args_parsing_result(res);

    assert(bool_flag->value.bool_value == true);
    assert(bool_flag->value_source == FLAG_VALUE_SOURCE_ENV);

    assert_string_equal("env_value", string_flag->value.string_value);
    assert(string_flag->value_source == FLAG_VALUE_SOURCE_ENV);
  }

  unsetenv("FOO_1");
  unsetenv("FOO_2");

  free_cli_app(app);
}

static void test_cli_app_parse_args_errors() {
  { // negative argc
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    const char *argv[] = {"foo", "bar"};

    cli_args_parsing_result_t *res = cli_app_parse_args(app, argv, -1);

    assert(res->code == FLAGS_PARSING_INVALID_ARGUMENTS);
    assert_string_equal("invalid arguments to cli_app_parse_args",
                        res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }

  { // NULL argv
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    cli_args_parsing_result_t *res = cli_app_parse_args(app, NULL, 999);

    assert(res->code == FLAGS_PARSING_INVALID_ARGUMENTS);
    assert_string_equal("invalid arguments to cli_app_parse_args",
                        res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }

  { // unknown flag
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    cli_app_add_flag(app, &EXAMPLE_BOOL_FLAG);

    cli_args_parsing_result_t *res =
        cli_app_parse_args(app, (const char *[]){"-b", "--unknown-flag"}, 2);

    assert(res->code == FLAGS_PARSING_UNKNOWN_FLAG);
    assert_string_equal("unknown flag: --unknown-flag", res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }

  { // full bool flag match
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    cli_app_add_flag(app, &EXAMPLE_BOOL_FLAG);

    cli_args_parsing_result_t *res =
        cli_app_parse_args(app, (const char *[]){"--bool-flagFOO"}, 1);

    assert(res->code == FLAGS_PARSING_UNKNOWN_FLAG);
    assert_string_equal("unknown flag: --bool-flagFOO", res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }

  { // short bool flag match
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    cli_app_add_flag(app, &EXAMPLE_BOOL_FLAG);

    cli_args_parsing_result_t *res =
        cli_app_parse_args(app, (const char *[]){"-bFOO"}, 1);

    assert(res->code == FLAGS_PARSING_UNKNOWN_FLAG);
    assert_string_equal("unknown flag: -bFOO", res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }

  { // bool flag in form --flag=value with wrong value
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    cli_app_add_flag(app, &EXAMPLE_BOOL_FLAG);

    cli_args_parsing_result_t *res =
        cli_app_parse_args(app, (const char *[]){"--bool-flag=not a bool"}, 1);

    assert(res->code == FLAGS_PARSING_INVALID_VALUE);
    assert_string_equal("invalid value [not a bool] for boolean flag --bool-flag",
                        res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }

  { // string flag in form --flag=value, but without value
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    cli_app_add_flag(app, &EXAMPLE_STRING_FLAG);

    cli_args_parsing_result_t *res =
        cli_app_parse_args(app, (const char *[]){"--string-flag="}, 1);

    assert(res->code == FLAGS_PARSING_MISSING_VALUE);
    assert_string_equal("missing value for flag --string-flag", res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }

  { // strings flag in form --flag=value, but without value
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    cli_app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

    cli_args_parsing_result_t *res =
        cli_app_parse_args(app, (const char *[]){"--strings-flag="}, 1);

    assert(res->code == FLAGS_PARSING_MISSING_VALUE);
    assert_string_equal("missing value for flag --strings-flag", res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }

  { // full string flag match
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    cli_app_add_flag(app, &EXAMPLE_STRING_FLAG);

    cli_args_parsing_result_t *res = cli_app_parse_args(
        app, (const char *[]){"--string-flagFOO", "value"}, 2);

    assert(res->code == FLAGS_PARSING_UNKNOWN_FLAG);
    assert_string_equal("unknown flag: --string-flagFOO", res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }

  { // short string flag match
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    cli_app_add_flag(app, &EXAMPLE_STRING_FLAG);

    cli_args_parsing_result_t *res =
        cli_app_parse_args(app, (const char *[]){"-sFOO", "value"}, 2);

    assert(res->code == FLAGS_PARSING_UNKNOWN_FLAG);
    assert_string_equal("unknown flag: -sFOO", res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }

  { // full string flag match
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    cli_app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

    cli_args_parsing_result_t *res = cli_app_parse_args(
        app, (const char *[]){"--strings-flagFOO", "value"}, 2);

    assert(res->code == FLAGS_PARSING_UNKNOWN_FLAG);
    assert_string_equal("unknown flag: --strings-flagFOO", res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }

  { // short string flag match
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    cli_app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

    cli_args_parsing_result_t *res =
        cli_app_parse_args(app, (const char *[]){"-mFOO", "value"}, 2);

    assert(res->code == FLAGS_PARSING_UNKNOWN_FLAG);
    assert_string_equal("unknown flag: -mFOO", res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }

  { // duplicate bool flag
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    cli_app_add_flag(app, &EXAMPLE_BOOL_FLAG);

    cli_args_parsing_result_t *res =
        cli_app_parse_args(app, (const char *[]){"-b", "--bool-flag"}, 2);

    assert(res->code == FLAGS_PARSING_DUPLICATE_FLAG);
    assert_string_equal("duplicate boolean flag: --bool-flag", res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }

  { // duplicate string flag
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    cli_app_add_flag(app, &EXAMPLE_STRING_FLAG);

    cli_args_parsing_result_t *res = cli_app_parse_args(
        app, (const char *[]){"--string-flag", "value1", "-s", "value2"}, 4);

    assert(res->code == FLAGS_PARSING_DUPLICATE_FLAG);
    assert_string_equal("duplicate flag: -s", res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }

  { // string flag without value
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    cli_app_add_flag(app, &EXAMPLE_STRING_FLAG);

    cli_args_parsing_result_t *res =
        cli_app_parse_args(app, (const char *[]){"--string-flag"}, 1);

    assert(res->code == FLAGS_PARSING_MISSING_VALUE);
    assert_string_equal("missing value for flag --string-flag", res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }

  { // string flag with CRLF
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    cli_app_add_flag(app, &EXAMPLE_STRING_FLAG);

    cli_args_parsing_result_t *res = cli_app_parse_args(
        app, (const char *[]){"--string-flag", "invalid\r\nvalue"}, 2);

    assert(res->code == FLAGS_PARSING_INVALID_VALUE);
    assert_string_equal("invalid characters in value for flag --string-flag",
                        res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }

  { // string flag in form --flag=value with wrong value
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    cli_app_add_flag(app, &EXAMPLE_STRING_FLAG);

    cli_args_parsing_result_t *res =
        cli_app_parse_args(app, (const char
        *[]){"--string-flag=invalid\r\n\t\n"}, 1);

    assert(res->code == FLAGS_PARSING_INVALID_VALUE);
    assert_string_equal(
        "invalid characters in value for flag --string-flag",
        res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }

  { // missing value for strings flag
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    cli_app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

    cli_args_parsing_result_t *res =
        cli_app_parse_args(app, (const char *[]){"--strings-flag"}, 1);

    assert(res->code == FLAGS_PARSING_MISSING_VALUE);
    assert_string_equal("missing value for flag --strings-flag", res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }

  { // strings flag with CRLF
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    cli_app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

    cli_args_parsing_result_t *res = cli_app_parse_args(
        app, (const char *[]){"--strings-flag", "invalid\r\nvalue"}, 2);

    assert(res->code == FLAGS_PARSING_INVALID_VALUE);
    assert_string_equal("invalid characters in value for flag --strings-flag",
                        res->message);

    free_cli_args_parsing_result(res);
    free_cli_app(app);
  }
}

static void test_cli_parse_command_string(void) {
  cli_command_parsing_result_t *result = NULL;

  { // Empty string
    result = cli_parse_command_string("");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 0);
    assert(result->argv == NULL);
    free_cli_command_parsing_result(result);
  }

  { // NULL string
    result = cli_parse_command_string(NULL);
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 0);
    assert(result->argv == NULL);
    free_cli_command_parsing_result(result);
  }

  { // Single argument
    result = cli_parse_command_string("echo");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 1);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(result->argv[1] == NULL);
    free_cli_command_parsing_result(result);
  }

  { // Multiple arguments
    result = cli_parse_command_string("echo hello world");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 3);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello") == 0);
    assert(strcmp(result->argv[2], "world") == 0);
    assert(result->argv[3] == NULL);
    free_cli_command_parsing_result(result);
  }

  { // Multiple spaces between arguments
    result = cli_parse_command_string("echo   hello    world");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 3);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello") == 0);
    assert(strcmp(result->argv[2], "world") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Leading and trailing spaces
    result = cli_parse_command_string("  echo hello  ");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Tabs as separators
    result = cli_parse_command_string("echo\thello\tworld");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 3);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello") == 0);
    assert(strcmp(result->argv[2], "world") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Single quoted argument
    result = cli_parse_command_string("echo 'hello world'");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello world") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Double quoted argument
    result = cli_parse_command_string("echo \"hello world\"");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello world") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Empty single quotes
    result = cli_parse_command_string("echo ''");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Empty double quotes
    result = cli_parse_command_string("echo \"\"");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Quote concatenation
    result = cli_parse_command_string("echo hello'world'test");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "helloworldtest") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Mixed quotes concatenation
    result = cli_parse_command_string("echo 'hello'\"world\"");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "helloworld") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Escaped space
    result = cli_parse_command_string("echo hello\\ world");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello world") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Escaped quote in double quotes
    result = cli_parse_command_string("echo \"hello\\\"world\"");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello\"world") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Backslash in single quotes (literal)
    result = cli_parse_command_string("echo 'hello\\world'");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello\\world") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Escaped backslash
    result = cli_parse_command_string("echo hello\\\\world");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello\\world") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Single quote inside double quotes
    result = cli_parse_command_string("echo \"it's fine\"");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "it's fine") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Double quote inside single quotes
    result = cli_parse_command_string("echo 'say \"hello\"'");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "say \"hello\"") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Unterminated single quote
    result = cli_parse_command_string("echo 'hello");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_UNTERMINATED_SINGLE_QUOTE);
    free_cli_command_parsing_result(result);
  }

  { // Unterminated double quote
    result = cli_parse_command_string("echo \"hello");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_UNTERMINATED_DOUBLE_QUOTE);
    free_cli_command_parsing_result(result);
  }

  { // Trailing backslash
    result = cli_parse_command_string("echo hello\\");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_TRAILING_BACKSLASH);
    free_cli_command_parsing_result(result);
  }

  { // Complex command with multiple quote types
    result = cli_parse_command_string(
        "git commit -m 'fix: update \"version\" number'");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 4);
    assert(strcmp(result->argv[0], "git") == 0);
    assert(strcmp(result->argv[1], "commit") == 0);
    assert(strcmp(result->argv[2], "-m") == 0);
    assert(strcmp(result->argv[3], "fix: update \"version\" number") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Special characters
    result = cli_parse_command_string("echo !@#$%^&*()");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "!@#$%^&*()") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Escaped newline and tab characters
    result = cli_parse_command_string("echo hello\\nworld\\ttab");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hellonworldttab") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Only whitespace
    result = cli_parse_command_string("   \t  \t   ");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 0);
    assert(result->argv != NULL);
    assert(result->argv[0] == NULL);
    free_cli_command_parsing_result(result);
  }

  { // Only quotes
    result = cli_parse_command_string("''\"\"");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 1);
    assert(strcmp(result->argv[0], "") == 0);
    free_cli_command_parsing_result(result);
  }

  { // Only quotes
    result = cli_parse_command_string("cmd'arg1 arg2'\"arg3\"");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 1);
    assert(strcmp(result->argv[0], "cmdarg1 arg2arg3") == 0);
    free_cli_command_parsing_result(result);
  }
}

int main() {
  test_cli_app_add_flag();

  test_help_nothing();
  test_help_bool_flag_only();
  test_help_bool_and_string_flags();
  test_help_bool_string_and_strings_flags();
  test_help_with_custom_flags();

  test_cli_app_parse_args_common();
  test_cli_app_parse_args_flags_with_equals_sign_long_form();
  test_cli_app_parse_args_flags_with_equals_sign_short_form();
  test_cli_app_parse_args_defaults();
  test_cli_app_parse_args_empty();
  test_cli_app_parse_args_env_vars();
  test_cli_app_parse_args_double_run();
  test_cli_app_parse_args_errors();

  test_cli_parse_command_string();

  return 0;
}
