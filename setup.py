from setuptools import setup, find_packages

setup(
    name="NSTAR",
    version="1.0",
    packages=find_packages(where="src", exclude=("test",)),
    package_dir={"": "src"},
    entry_points="""\
        [console_scripts]
        nstar-remediation = cli:cli
    """
)
