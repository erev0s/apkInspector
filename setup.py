from setuptools import setup, find_packages

setup(
    name='apkInspector',
    version='1.3.0',
    author='erev0s',
    author_email='projects@erev0s.com',
    description='apkInspector is a tool designed to provide detailed insights into '
                'the zip structure of APK files, offering the '
                'capability to extract content and decode the AndroidManifest.xml '
                'file.',
    url='https://github.com/erev0s/apkInspector',
    packages=find_packages(),
    python_requires='>=3.5',
    entry_points={
        'console_scripts': [
            'apkInspector=apkInspectorCLI.main:main',
        ],
    },
)
