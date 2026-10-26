from typing import Any, Callable, Dict, List, Optional, Union

class Error(Exception): ...
class SyntaxError(Error): ...
class TimeoutError(Error): ...
class WarningError(Error): ...

class StringMatch:
    identifier: str
    instances: List[Any]

class Match:
    rule: str
    namespace: str
    tags: List[str]
    meta: Dict[str, Any]
    strings: List[StringMatch]

class Rule:
    identifier: str
    is_private: bool
    is_global: bool
    tags: List[str]
    meta: Dict[str, Any]

class Rules:
    def match(
        self,
        filepath: Optional[str] = ...,
        pid: Optional[int] = ...,
        data: Optional[Union[bytes, str]] = ...,
        timeout: Optional[int] = ...,
        modules_data: Optional[Dict[str, Any]] = ...,
        modules_callback: Optional[Callable[..., Any]] = ...,
        which_callbacks: Optional[int] = ...,
        callback: Optional[Callable[..., Any]] = ...,
    ) -> List[Match]: ...
    def __iter__(self) -> Any: ...

def compile(
    filepath: Optional[str] = ...,
    filepaths: Optional[Dict[str, str]] = ...,
    source: Optional[str] = ...,
    sources: Optional[Dict[str, str]] = ...,
    includes: bool = ...,
    include_callback: Optional[Callable[[str, str, str], Optional[str]]] = ...,
    externals: Optional[Dict[str, Any]] = ...,
    error_on_warning: bool = ...,
) -> Rules: ...
