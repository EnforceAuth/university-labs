package rego_essentials.m2

import rego.v1

default allow := false

# BUG on purpose: any role except guest can do anything.
allow if input.user.role != "guest"
