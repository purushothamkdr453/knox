"""
Apache Software License 2.0

Copyright (c) 2020, 8x8, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""


class StoreObject:
    """Metadata interface for objects being persisted in a backend"""
    _name: str  #: Name of the objects store key
    _path: str  #: Path from store mount point to find store key
    _body: str  #: Content that will be persisted
    _info: str  #: Metadata about the object being stored, rendered using jinja template
    _version: int  #: Store revision

    def __init__(self, name: str, path: str, body: str, info: str) -> None:
        """Constructor for StoreObject"""

        self._name = name  #: [TODO 5/16/20] ljohnson name validator
        self._path = path  #: [TODO 5/16/20] ljohnson path validator
        self._body = body  #: [TODO 5/16/20] ljohnson body and info validator
        self._info = info

    @property
    def name(self) -> str:
        """Object name"""
        return self._name

    @property
    def path(self) -> str:
        """Path attribute"""
        return self._path

    @property
    def path_name(self) -> str:
        """Convienence method to generate path/name for store"""
        return self._path + self._name

    @property
    def body(self) -> str:
        """Content to persist, typically JSON"""
        return self._body

    @property
    def info(self) -> str:
        """Object metadata"""
        return self._info

    @property
    def version(self) -> int:
        """Object version"""
        return self._version

    @path.setter
    def path(self, value: str) -> None:
        self._path = value

    @body.setter
    def body(self, value: str) -> None:
        self._body = value

    @info.setter
    def info(self, value: str) -> None:
        self._info = value

    @version.setter
    def version(self, value: int) -> None:
        self._version = value