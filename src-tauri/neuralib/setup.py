from setuptools import setup, find_packages

setup(
    name='neuralib',
    version='0.2.3',
    packages=find_packages(),
    install_requires=[
        'transformers',
        'numpy',
        'onnxruntime',
    ],
    author='MSA',
    author_email='admin@sufi.win',
    description='A Neural-AV library for identifying and classifying malware',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    'Operating System :: OS Independent'
    ],
    python_requires='>=3.6',
    keywords='neural-av neuralib neural av malware antivirus',
)





