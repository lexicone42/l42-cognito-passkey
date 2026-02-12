#!/usr/bin/env python3
"""CDK app entry point for the L42 Token Handler Lambda deployment."""

import aws_cdk as cdk

from stack import L42TokenHandlerStack

app = cdk.App()
L42TokenHandlerStack(app, "L42TokenHandler")
app.synth()
