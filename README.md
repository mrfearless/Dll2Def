# Dll2Def

Command line tool to create an export defintion file from a dynamic link library

**Usage**

```
Dll2Def [ /? | -? ]
Dll2Def <infilename> [<outfilename>]
Dll2Def <infilespec> [<outfolder>]
Dll2Def <infolder> [<outfolder>]
```

**Switches**:

- `/?` | `-?` - Displays help.

**Parameters**:

- `infilename` - name of a valid dll file to process. Supports the use of wildcards `*` and `?` for batch operations.
- `outfilename` - (optional) is name of the definition file to create. Defaults to the `infilename` with `.def` extension. **Note:** cannot use wildcards if specifying `outfilename`.
- `infilespec` - is the use of wildcards (`*.dll`) to process.
- `outfolder` - (optional) is the folder to output `.def` files to.
- `infolder` - (optional) is the folder to process. (assumes `*.*`)

## Building

Dll2Def makes use of the [Console](https://github.com/mrfearless/libraries/tree/master/Console) x86 library, which can be located in the [libraries](https://github.com/mrfearless/libraries) repository.