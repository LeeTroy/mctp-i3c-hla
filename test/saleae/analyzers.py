# Minimal stand-in for the Logic 2 `saleae.analyzers` module, for running tests outside Logic 2.


class AnalyzerFrame:
    def __init__(self, type, start_time, end_time, data=None):
        self.type = type
        self.start_time = start_time
        self.end_time = end_time
        self.data = data or {}


class HighLevelAnalyzer:
    pass


class StringSetting:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class ChoicesSetting:
    def __init__(self, choices, **kwargs):
        self.choices = choices
