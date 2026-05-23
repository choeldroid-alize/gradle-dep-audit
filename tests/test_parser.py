"""Tests for the Gradle dependency tree parser."""

import pytest
from gradle_dep_audit.parser import parse_dependency_line, parse_dependency_tree, Dependency


SAMPLE_TREE = """\
runtimeClasspath - Runtime classpath of source set 'main'.
+--- com.google.guava:guava:30.1-jre
|    +--- com.google.code.findbugs:jsr305:3.0.2
|    \\--- com.google.errorprone:error_prone_annotations:2.5.1
+--- org.slf4j:slf4j-api:1.7.30 -> 1.7.36
\\--- org.apache.commons:commons-lang3:3.12.0
"""


@pytest.mark.parametrize("line,expected", [
    (
        "+--- com.google.guava:guava:30.1-jre",
        Dependency("com.google.guava", "guava", "30.1-jre"),
    ),
    (
        "+--- org.slf4j:slf4j-api:1.7.30 -> 1.7.36",
        Dependency("org.slf4j", "slf4j-api", "1.7.36", requested_version="1.7.30"),
    ),
    (
        "Not a dependency line",
        None,
    ),
])
def test_parse_dependency_line(line, expected):
    result = parse_dependency_line(line)
    assert result == expected


def test_parse_dependency_tree_returns_unique_deps():
    deps = parse_dependency_tree(SAMPLE_TREE)
    coordinates = [d.coordinate for d in deps]
    assert len(coordinates) == len(set(coordinates)), "Duplicate dependencies found"


def test_parse_dependency_tree_count():
    deps = parse_dependency_tree(SAMPLE_TREE)
    assert len(deps) == 5


def test_parse_dependency_tree_version_resolution():
    deps = parse_dependency_tree(SAMPLE_TREE)
    slf4j = next(d for d in deps if d.artifact == "slf4j-api")
    assert slf4j.version == "1.7.36"
    assert slf4j.requested_version == "1.7.30"


def test_parse_empty_tree():
    assert parse_dependency_tree("") == []
    assert parse_dependency_tree("No dependencies here.\n") == []
