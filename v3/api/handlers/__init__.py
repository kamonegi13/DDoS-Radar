"""The handler layer: functions from a read context to a response.

Every module here is a pure projection. No module imports a web
framework, decides who may call it, or holds a writer — those three
absences are what make the layer testable without a server, and each one
is asserted by a test rather than requested by a convention.
"""
