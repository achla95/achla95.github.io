---
title: "Hackthebox Onlyforyou"
date: 2023-04-26T22:02:29+02:00
draft: false
---

On Onlyforyou we exploit a python code vulnerability in the source code to read local file (LFI).
From this we can see another misconfiguration which allows us to bypass regex verification and get remote code execution.
Next, we'll do cypher injection to get user flag.
Finally, for root we abuse of python pip download vulnerabilites.

<!--more-->
