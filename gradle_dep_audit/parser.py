"""Parser for Gradle dependency tree output."""

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Dependency:
    group: str
    artifact: str
    version: str
    requested_version: Optional[str] = None
    children: list = field(default_factory=list)

    @property
    def coordinate(self) -> str:
        return f"{self.group}:{self.artifact}:{self.version}"

    def __repr__(self) -> str:
        return f"Dependency({self.coordinate})"


# Matches lines like: +--- com.google.guava:guava:30.1-jre
# or:                  \--- org.slf4j:slf4j-api:1.7.30 -> 1.7.36
DEP_LINE_RE = re.compile(
    r"^[|\\+` -]+([\w.\-]+):([\w.\-]+):([\w.\-]+)(?:\s*->\s*([\w.\-]+))?"
)


def parse_dependency_line(line: str) -> Optional[Dependency]:
    """Parse a single line from gradle dependency output."""
    match = DEP_LINE_RE.match(line)
    if not match:
        return None
    group, artifact, raw_version, resolved = match.groups()
    version = resolved if resolved else raw_version
    requested = raw_version if resolved else None
    return Dependency(group=group, artifact=artifact, version=version,
                      requested_version=requested)


def parse_dependency_tree(text: str) -> list[Dependency]:
    """Parse full gradle dependency tree text into a flat list of dependencies."""
    deps = []
    seen = set()
    for line in text.splitlines():
        dep = parse_dependency_line(line)
        if dep and dep.coordinate not in seen:
            seen.add(dep.coordinate)
            deps.append(dep)
    return deps
