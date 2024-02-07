# IniParserEx
one file only parser.
extended with list and map.
inspired by Unreal config
https://docs.unrealengine.com/4.26/en-US/ProductionPipelines/ConfigurationFiles/

```
// usage like:

[Target]
# comment
; comment
+TestList=A
+TestList=B

test.TestListMember=[A.asd, B]
test.TestMapMember=(A.A=10, B.C=20)
test.TestComplex=[(A=10, B=20), (A=20, B=30)]
test.TestComplex2=(A=[1, 2, 3], B=[2, 3, 4])
```