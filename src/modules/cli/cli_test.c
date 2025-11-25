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

void test_app_add_flag() {
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

  assert_string_equal(string_flag->value.string_value, "default");

  assert(strings_flag->value.strings_value.count == 3);
  assert_string_equal(strings_flag->value.strings_value.list[0], "one");
  assert_string_equal(strings_flag->value.strings_value.list[1], "two");
  assert_string_equal(strings_flag->value.strings_value.list[2], "three");

  free_cli_app(app);
}

void test_help_nothing() {
  cli_app_state_t *app = new_cli_app(&(cli_app_meta_t){0});

  char *help = app_help_text(app);
  assert_string_equal("app", help);

  free(help);
  free_cli_app(app);
}

void test_help_bool_flag_only() {
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

void test_help_bool_and_string_flags() {
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

void test_help_bool_string_and_strings_flags() {
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

void test_help_with_custom_flags() {
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

void test_app_parse_args_common() {
  cli_app_state_t *app = new_cli_app(&EXAMPLE_APP);

  const flag_state_t *bool_flag = app_add_flag(app, &EXAMPLE_BOOL_FLAG);
  const flag_state_t *string_flag = app_add_flag(app, &EXAMPLE_STRING_FLAG);
  const flag_state_t *strings_flag = app_add_flag(app, &EXAMPLE_STRINGS_FLAG);

  const char *argv[] = {
    "--bool-flag",
    "-s", "custom_value",
    "--strings-flag", "first",
    "-m", "second",
    "positional1",
    "positional2"
  };

  const parsing_result_t result = app_parse_args(app, argv, sizeof(argv) / sizeof(argv[0]));

  assert(result.code == FLAGS_PARSING_OK);

  free_parsing_result(result);

  assert(bool_flag->value.bool_value == true);
  assert_string_equal(string_flag->value.string_value, "custom_value");

  printf("%d\n", (int) strings_flag->value.strings_value.count);
  assert(strings_flag->value.strings_value.count == 2);
  assert_string_equal(strings_flag->value.strings_value.list[0], "first");
  assert_string_equal(strings_flag->value.strings_value.list[1], "second");

  assert(app->args.count == 2);
  assert_string_equal(app->args.list[0], "positional1");
  assert_string_equal(app->args.list[1], "positional2");

  free_cli_app(app);
}

int main() {
  test_app_add_flag();

  test_help_nothing();
  test_help_bool_flag_only();
  test_help_bool_and_string_flags();
  test_help_bool_string_and_strings_flags();
  test_help_with_custom_flags();

  test_app_parse_args_common();

  return 0;
}
