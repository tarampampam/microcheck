#include "../../../lib/command/command.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
  test_cli_parse_command_string();

  return 0;
}
