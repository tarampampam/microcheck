#include "cli.h"
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const flag_meta_t EXAMPLE_BOOL_FLAG = {
    .short_name = "b",
    .long_name = "bool-flag",
    .description = "A boolean flag",
    .env_variable = "BOOL_FLAG",
    .type = FLAG_TYPE_BOOL,
    .default_value = {.bool_value = false},
};

static const flag_meta_t EXAMPLE_STRING_FLAG = {
    .short_name = "s",
    .long_name = "string-flag",
    .description = "A string flag",
    .env_variable = "STRING_FLAG",
    .type = FLAG_TYPE_STRING,
    .default_value = {.string_value = "default"},
};

static const flag_meta_t EXAMPLE_STRINGS_FLAG = {
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

void assert_string_equal(const char *expected, const char *actual) {
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

static void test_app_add_flag() {
  cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);
  assert(app != NULL);

  const flag_state_t *bool_flag = app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  assert(bool_flag != NULL);

  const flag_state_t *string_flag = app_add_flag(app, &EXAMPLE_STRING_FLAG);
  assert(string_flag != NULL);

  const flag_state_t *strings_flag = app_add_flag(app, &EXAMPLE_STRINGS_FLAG);
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

  char *help = app_help_text(app);
  assert_string_equal("app", help);

  free(help);
  free_cli_app(app);
}

static void test_help_bool_flag_only() {
  cli_app_state_t *app = new_cli_app(&(cli_app_meta_t){0});

  app_add_flag(app, &EXAMPLE_BOOL_FLAG);

  char *help = app_help_text(app);
  assert_string_equal("app\n\n"
                      "Options:\n"
                      "  -b, --bool-flag  A boolean flag [$BOOL_FLAG]",
                      help);

  free(help);
  free_cli_app(app);
}

static void test_help_bool_and_string_flags() {
  cli_app_state_t *app = new_cli_app(&(cli_app_meta_t){0});

  app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  app_add_flag(app, &EXAMPLE_STRING_FLAG);

  char *help = app_help_text(app);
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

  app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  app_add_flag(app, &EXAMPLE_STRING_FLAG);
  app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

  char *help = app_help_text(app);
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

  app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  app_add_flag(app, &EXAMPLE_STRING_FLAG);
  app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

  app_add_flag(app, &(flag_meta_t){
                        .short_name = "x",
                        .description = "Short only flag",
                        .type = FLAG_TYPE_BOOL,
                    });
  app_add_flag(app, &(flag_meta_t){
                        .long_name = "xxx",
                        .description = "Long only flag",
                        .type = FLAG_TYPE_BOOL,
                    });

  char *help = app_help_text(app);

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

static void test_app_parse_args_common() {
  cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

  const flag_state_t *bool_flag = app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  const flag_state_t *string_flag = app_add_flag(app, &EXAMPLE_STRING_FLAG);
  const flag_state_t *strings_flag = app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

  const char *argv[] = {"--bool-flag",    "-s",          "custom_value",
                        "--strings-flag", "first",       "-m",
                        "second",         "positional1", "positional2"};

  args_parsing_result_t *res =
      app_parse_args(app, argv, sizeof(argv) / sizeof(argv[0]));

  assert(res->code == FLAGS_PARSING_OK);
  assert(res->message == NULL);

  free_args_parsing_result(res);

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

static void test_app_parse_args_defaults() {
  cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

  const flag_state_t *bool_flag = app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  const flag_state_t *string_flag = app_add_flag(app, &EXAMPLE_STRING_FLAG);
  const flag_state_t *strings_flag = app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

  const char *argv[] = {"foo"};

  args_parsing_result_t *res =
      app_parse_args(app, argv, sizeof(argv) / sizeof(argv[0]));

  assert(res->code == FLAGS_PARSING_OK);
  assert(res->message == NULL);

  free_args_parsing_result(res);

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

static void test_app_parse_args_empty() {
  cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

  const flag_state_t *bool_flag = app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  const flag_state_t *string_flag = app_add_flag(app, &EXAMPLE_STRING_FLAG);
  const flag_state_t *strings_flag = app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

  const char *argv[] = {NULL};

  args_parsing_result_t *res = app_parse_args(app, argv, 0);

  assert(res->code == FLAGS_PARSING_OK);
  assert(res->message == NULL);

  free_args_parsing_result(res);

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

static void test_app_parse_args_env_vars() {
  cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

  const flag_state_t *bool_flag = app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  const flag_state_t *string_flag = app_add_flag(app, &EXAMPLE_STRING_FLAG);
  const flag_state_t *strings_flag = app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

  // set environment values
  setenv(EXAMPLE_BOOL_FLAG.env_variable, "true", 1);
  setenv(EXAMPLE_STRING_FLAG.env_variable, "env_value", 1);
  setenv(EXAMPLE_STRINGS_FLAG.env_variable, "env1,env2", 1);

  const char *argv[] = {NULL};

  args_parsing_result_t *res = app_parse_args(app, argv, 0);

  assert(res->code == FLAGS_PARSING_OK);
  assert(res->message == NULL);

  free_args_parsing_result(res);

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

static void test_app_parse_args_double_run() {
  cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

  flag_state_t *bool_flag = app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  flag_state_t *string_flag = app_add_flag(app, &EXAMPLE_STRING_FLAG);

  // set environment values
  setenv("FOO_1", "true", 1);
  setenv("FOO_2", "env_value", 1);

  const char *argv[] = {NULL};

  { // first run - should not pick up env vars yet
    args_parsing_result_t *res = app_parse_args(app, argv, 0);

    assert(res->code == FLAGS_PARSING_OK);
    assert(res->message == NULL);

    free_args_parsing_result(res);

    assert(bool_flag->value.bool_value == false);
    assert(bool_flag->value_source == FLAG_VALUE_SOURCE_DEFAULT);

    assert_string_equal("default", string_flag->value.string_value);
    assert(string_flag->value_source == FLAG_VALUE_SOURCE_DEFAULT);
  }

  { // second run - after changing env_variable names
    bool_flag->env_variable = strdup("FOO_1");   // <-- change env variable name
    string_flag->env_variable = strdup("FOO_2"); // <-- change env variable name

    args_parsing_result_t *res = app_parse_args(app, argv, 0);

    assert(res->code == FLAGS_PARSING_OK);
    assert(res->message == NULL);

    free_args_parsing_result(res);

    assert(bool_flag->value.bool_value == true);
    assert(bool_flag->value_source == FLAG_VALUE_SOURCE_ENV);

    assert_string_equal("env_value", string_flag->value.string_value);
    assert(string_flag->value_source == FLAG_VALUE_SOURCE_ENV);
  }

  unsetenv("FOO_1");
  unsetenv("FOO_2");

  free_cli_app(app);
}

static void test_app_parse_args_errors() {
  { // negative argc
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    const char *argv[] = {"foo", "bar"};

    args_parsing_result_t *res = app_parse_args(app, argv, -1);

    assert(res->code == FLAGS_PARSING_INVALID_ARGUMENTS);
    assert_string_equal("invalid arguments to app_parse_args", res->message);

    free_args_parsing_result(res);
    free_cli_app(app);
  }

  { // NULL argv
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    args_parsing_result_t *res = app_parse_args(app, NULL, 999);

    assert(res->code == FLAGS_PARSING_INVALID_ARGUMENTS);
    assert_string_equal("invalid arguments to app_parse_args", res->message);

    free_args_parsing_result(res);
    free_cli_app(app);
  }

  { // unknown flag
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    app_add_flag(app, &EXAMPLE_BOOL_FLAG);

    args_parsing_result_t *res =
        app_parse_args(app, (const char *[]){"-b", "--unknown-flag"}, 2);

    assert(res->code == FLAGS_PARSING_UNKNOWN_FLAG);
    assert_string_equal("unknown flag: --unknown-flag", res->message);

    free_args_parsing_result(res);
    free_cli_app(app);
  }

  { // duplicate bool flag
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    app_add_flag(app, &EXAMPLE_BOOL_FLAG);

    args_parsing_result_t *res =
        app_parse_args(app, (const char *[]){"-b", "--bool-flag"}, 2);

    assert(res->code == FLAGS_PARSING_DUPLICATE_FLAG);
    assert_string_equal("duplicate flag: --bool-flag", res->message);

    free_args_parsing_result(res);
    free_cli_app(app);
  }

  { // duplicate string flag
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    app_add_flag(app, &EXAMPLE_STRING_FLAG);

    args_parsing_result_t *res = app_parse_args(
        app, (const char *[]){"--string-flag", "value1", "-s", "value2"}, 4);

    assert(res->code == FLAGS_PARSING_DUPLICATE_FLAG);
    assert_string_equal("duplicate flag: -s", res->message);

    free_args_parsing_result(res);
    free_cli_app(app);
  }

  { // string flag without value
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    app_add_flag(app, &EXAMPLE_STRING_FLAG);

    args_parsing_result_t *res =
        app_parse_args(app, (const char *[]){"--string-flag"}, 1);

    assert(res->code == FLAGS_PARSING_MISSING_VALUE);
    assert_string_equal("missing value for flag --string-flag", res->message);

    free_args_parsing_result(res);
    free_cli_app(app);
  }

  { // string flag with CRLF
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    app_add_flag(app, &EXAMPLE_STRING_FLAG);

    args_parsing_result_t *res = app_parse_args(
        app, (const char *[]){"--string-flag", "invalid\r\nvalue"}, 2);

    assert(res->code == FLAGS_PARSING_INVALID_VALUE);
    assert_string_equal("invalid characters in value for flag --string-flag",
                        res->message);

    free_args_parsing_result(res);
    free_cli_app(app);
  }

  { // missing value for strings flag
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

    args_parsing_result_t *res =
        app_parse_args(app, (const char *[]){"--strings-flag"}, 1);

    assert(res->code == FLAGS_PARSING_MISSING_VALUE);
    assert_string_equal("missing value for flag --strings-flag", res->message);

    free_args_parsing_result(res);
    free_cli_app(app);
  }

  { // strings flag with CRLF
    cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

    app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

    args_parsing_result_t *res = app_parse_args(
        app, (const char *[]){"--strings-flag", "invalid\r\nvalue"}, 2);

    assert(res->code == FLAGS_PARSING_INVALID_VALUE);
    assert_string_equal("invalid characters in value for flag --strings-flag",
                        res->message);

    free_args_parsing_result(res);
    free_cli_app(app);
  }
}

static void test_parse_command_string(void) {
  command_parsing_result_t *result = NULL;

  { // Empty string
    result = parse_command_string("");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 0);
    assert(result->argv == NULL);
    free_command_parsing_result(result);
  }

  { // NULL string
    result = parse_command_string(NULL);
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 0);
    assert(result->argv == NULL);
    free_command_parsing_result(result);
  }

  { // Single argument
    result = parse_command_string("echo");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 1);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(result->argv[1] == NULL);
    free_command_parsing_result(result);
  }

  { // Multiple arguments
    result = parse_command_string("echo hello world");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 3);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello") == 0);
    assert(strcmp(result->argv[2], "world") == 0);
    assert(result->argv[3] == NULL);
    free_command_parsing_result(result);
  }

  { // Multiple spaces between arguments
    result = parse_command_string("echo   hello    world");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 3);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello") == 0);
    assert(strcmp(result->argv[2], "world") == 0);
    free_command_parsing_result(result);
  }

  { // Leading and trailing spaces
    result = parse_command_string("  echo hello  ");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello") == 0);
    free_command_parsing_result(result);
  }

  { // Tabs as separators
    result = parse_command_string("echo\thello\tworld");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 3);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello") == 0);
    assert(strcmp(result->argv[2], "world") == 0);
    free_command_parsing_result(result);
  }

  { // Single quoted argument
    result = parse_command_string("echo 'hello world'");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello world") == 0);
    free_command_parsing_result(result);
  }

  { // Double quoted argument
    result = parse_command_string("echo \"hello world\"");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello world") == 0);
    free_command_parsing_result(result);
  }

  { // Empty single quotes
    result = parse_command_string("echo ''");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "") == 0);
    free_command_parsing_result(result);
  }

  { // Empty double quotes
    result = parse_command_string("echo \"\"");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "") == 0);
    free_command_parsing_result(result);
  }

  { // Quote concatenation
    result = parse_command_string("echo hello'world'test");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "helloworldtest") == 0);
    free_command_parsing_result(result);
  }

  { // Mixed quotes concatenation
    result = parse_command_string("echo 'hello'\"world\"");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "helloworld") == 0);
    free_command_parsing_result(result);
  }

  { // Escaped space
    result = parse_command_string("echo hello\\ world");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello world") == 0);
    free_command_parsing_result(result);
  }

  { // Escaped quote in double quotes
    result = parse_command_string("echo \"hello\\\"world\"");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello\"world") == 0);
    free_command_parsing_result(result);
  }

  { // Backslash in single quotes (literal)
    result = parse_command_string("echo 'hello\\world'");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello\\world") == 0);
    free_command_parsing_result(result);
  }

  { // Escaped backslash
    result = parse_command_string("echo hello\\\\world");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hello\\world") == 0);
    free_command_parsing_result(result);
  }

  { // Single quote inside double quotes
    result = parse_command_string("echo \"it's fine\"");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "it's fine") == 0);
    free_command_parsing_result(result);
  }

  { // Double quote inside single quotes
    result = parse_command_string("echo 'say \"hello\"'");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "say \"hello\"") == 0);
    free_command_parsing_result(result);
  }

  { // Unterminated single quote
    result = parse_command_string("echo 'hello");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_UNTERMINATED_SINGLE_QUOTE);
    free_command_parsing_result(result);
  }

  { // Unterminated double quote
    result = parse_command_string("echo \"hello");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_UNTERMINATED_DOUBLE_QUOTE);
    free_command_parsing_result(result);
  }

  { // Trailing backslash
    result = parse_command_string("echo hello\\");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_TRAILING_BACKSLASH);
    free_command_parsing_result(result);
  }

  { // Complex command with multiple quote types
    result = parse_command_string("git commit -m 'fix: update \"version\" number'");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 4);
    assert(strcmp(result->argv[0], "git") == 0);
    assert(strcmp(result->argv[1], "commit") == 0);
    assert(strcmp(result->argv[2], "-m") == 0);
    assert(strcmp(result->argv[3], "fix: update \"version\" number") == 0);
    free_command_parsing_result(result);
  }

  { // Special characters
    result = parse_command_string("echo !@#$%^&*()");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "!@#$%^&*()") == 0);
    free_command_parsing_result(result);
  }

  { // Escaped newline and tab characters
    result = parse_command_string("echo hello\\nworld\\ttab");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 2);
    assert(strcmp(result->argv[0], "echo") == 0);
    assert(strcmp(result->argv[1], "hellonworldttab") == 0);
    free_command_parsing_result(result);
  }

  { // Only whitespace
    result = parse_command_string("   \t  \t   ");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 0);
    assert(result->argv != NULL);
    assert(result->argv[0] == NULL);
    free_command_parsing_result(result);
  }

  { // Only quotes
    result = parse_command_string("''\"\"");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 1);
    assert(strcmp(result->argv[0], "") == 0);
    free_command_parsing_result(result);
  }

  { // Only quotes
    result = parse_command_string("cmd'arg1 arg2'\"arg3\"");
    assert(result != NULL);
    assert(result->code == COMMAND_PARSING_OK);
    assert(result->argc == 1);
    assert(strcmp(result->argv[0], "cmdarg1 arg2arg3") == 0);
    free_command_parsing_result(result);
  }
}

int main() {
  test_app_add_flag();

  test_help_nothing();
  test_help_bool_flag_only();
  test_help_bool_and_string_flags();
  test_help_bool_string_and_strings_flags();
  test_help_with_custom_flags();

  test_app_parse_args_common();
  test_app_parse_args_defaults();
  test_app_parse_args_empty();
  test_app_parse_args_env_vars();
  test_app_parse_args_double_run();
  test_app_parse_args_errors();

  test_parse_command_string();

  return 0;
}
