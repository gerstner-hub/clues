#pragma once

// helper to return the literal string matching an enum or preprocessor constant value
#define CASE_ENUM_TO_STR(NAME) case NAME: return #NAME
