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
import os  # noqa: F401

from loguru import logger

from .store_engine import StoreEngine


class FileStoreEngine(StoreEngine):
    """"""
    __file_home: str

    def __init__(self, settings) -> None:
        """Constructor for FileStore"""
        super().__init__()
        self.__file_home = settings.FILE_HOME
        logger.debug(f'📂 File backend configuration loaded. {self.__file_home}')
