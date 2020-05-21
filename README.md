# Github Java CTF Submission: Kanav Gupta
Submission for the GitHub Security Lab CTF 4: CodeQL and Chill - The Java Edition

## Introduction

The challenge introduction aptly summarizes the issue: user controlled data being passed into the Bean Validation library function `ConstraintValidatorContext.buildConstraintViolationWithTemplate` which supports Java EL Expressions. Hence, remote code execution. That might seem to be the end of the issue, but it isn't. Getting an RCE wasn't as easy as just passing an EL expression. Some issues like lowercasing of the user input stopped us from getting the exploit. In this report I explain how I found specific user controlled data which flows into the target function using CodeQL, assess what requirements we have for a successful remote code execution and finally I present the exploit.

## Step 1: Data Flow and Taint Tracking Analysis

### 1.1 Sources
