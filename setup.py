from setuptools import setup, find_packages

setup(
    name='apkInspector',
    version='1.0.3',
    author='erev0s',
    author_email='projects@erev0s.com',
    description='apkInspector is a tool designed to provide detailed insights into '
                'the central directory and local headers of APK files, offering the '
                'capability to extract content and decode the AndroidManifest.xml '
                'file.',
    url='https://#',
    packages=find_packages(),
    python_requires='>=3.5',
    entry_points={
        'console_scripts': [
            'apkInspector=cli.apkInspector:main',
        ],
    },
)
