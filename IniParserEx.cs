using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace IniParserEx;

public enum TokenType
{
	None = 0,
	Identifier,
	Symbol,
	Const,
	Max = Const
}

public enum TokenConstType
{
	None = 0,
	Byte,
	Int,
	Int64,
	Bool,
	Float,
	Double,
	String,
	Char,
	Max = Char
}

public class Token
{
	public const int MaxNameSize = 1024;
	public const int MaxStringConstLength = 1024;
	private object RawTokenValue;

	public Token(int startPos, int startLine)
	{
		StartPos = startPos;
		StartLine = startLine;
	}

	public TokenConstType ConstType { get; private set; } = TokenConstType.None;

	public TokenType TokenType { get; set; } = TokenType.None;

	public int StartPos { get; private set; }
	public int StartLine { get; private set; }
	public StringBuilder Identifier { get; } = new();

	public T Get<T>()
	{
		return (T)RawTokenValue;
	}

	public void InitToken()
	{
		TokenType = TokenType.None;
		StartPos = 0;
		StartLine = 0;
		Identifier.Clear();
	}

	public string GetTokenName()
	{
		return Identifier.ToString();
	}

	public string GetConstantValue()
	{
		if (TokenType == TokenType.Const)
			switch (ConstType)
			{
				case TokenConstType.Byte:
					return Get<byte>().ToString();
				case TokenConstType.Int:
					return Get<int>().ToString();
				case TokenConstType.Int64:
					return Get<long>().ToString();
				case TokenConstType.Bool:
					return Get<bool>().ToString();
				case TokenConstType.Float:
					return Get<float>().ToString(CultureInfo.InvariantCulture);
				case TokenConstType.Double:
					return Get<double>().ToString(CultureInfo.InvariantCulture);
				case TokenConstType.String:
					return Get<string>();
				default:
					return "InvalidTypeForToken";
			}

		return "NotConstant";
	}

	public bool Matches(char c)
	{
		return TokenType == TokenType.Symbol
		       && Identifier[0] == c
		       && Identifier.Length == 1;
	}

	public bool Matches(string s)
	{
		return (TokenType == TokenType.Identifier || TokenType == TokenType.Symbol)
		       && s == Identifier.ToString();
	}

	public bool IsBool()
	{
		return ConstType == TokenConstType.Bool;
	}

	public void SetIdentifier(string s)
	{
		InitToken();
		TokenType = TokenType.Identifier;
		Identifier.Clear();
		Identifier.Append(s);
	}

	public void SetInt64(long i64)
	{
		ConstType = TokenConstType.Int64;
		TokenType = TokenType.Const;
		RawTokenValue = i64;
	}

	public void SetConstInt(int i)
	{
		ConstType = TokenConstType.Int;
		TokenType = TokenType.Const;
		RawTokenValue = i;
	}

	public void SetConstBool(bool b)
	{
		ConstType = TokenConstType.Bool;
		TokenType = TokenType.Const;
		RawTokenValue = b;
	}

	public void SetConstFloat(float f)
	{
		ConstType = TokenConstType.Float;
		TokenType = TokenType.Const;
		RawTokenValue = f;
	}

	public void SetConstDouble(double d)
	{
		ConstType = TokenConstType.Double;
		TokenType = TokenType.Const;
		RawTokenValue = d;
	}

	public void SetConstString(string s)
	{
		ConstType = TokenConstType.String;
		TokenType = TokenType.Const;
		RawTokenValue = s;
	}

	public void SetConstChar(char c)
	{
		ConstType = TokenConstType.Char;
		TokenType = TokenType.Const;
		RawTokenValue = c;
	}

	public bool GetConstInt(out int OutInt)
	{
		OutInt = 0;
		if (TokenType != TokenType.Const) return false;
		switch (ConstType)
		{
			case TokenConstType.Int64:
				OutInt = (int)Get<long>();
				return true;
			case TokenConstType.Int:
				OutInt = Get<int>();
				return true;
			case TokenConstType.Byte:
				OutInt = Get<byte>();
				return true;
			case TokenConstType.Float:
				OutInt = (int)Get<float>();
				return true;
			case TokenConstType.Double:
				OutInt = (int)Get<double>();
				return true;
			case TokenConstType.Bool:
				OutInt = Get<bool>() ? 1 : 0;
				return true;
			default:
				return false;
		}
	}

	public bool GetConstInt64(out long OutInt64)
	{
		OutInt64 = 0;
		if (TokenType != TokenType.Const) return false;
		switch (ConstType)
		{
			case TokenConstType.Int64:
				OutInt64 = Get<long>();
				return true;
			case TokenConstType.Int:
				OutInt64 = Get<int>();
				return true;
			case TokenConstType.Byte:
				OutInt64 = Get<byte>();
				return true;
			case TokenConstType.Float:
				OutInt64 = (int)Get<float>();
				return true;
			case TokenConstType.Double:
				OutInt64 = (int)Get<double>();
				return true;
			case TokenConstType.Bool:
				OutInt64 = Get<bool>() ? 1 : 0;
				return true;
			default:
				return false;
		}
	}

	public bool GetConstBool(out bool OutBool)
	{
		OutBool = false;
		if (TokenType != TokenType.Const) return false;
		switch (ConstType)
		{
			case TokenConstType.Int64:
				OutBool = Get<long>() != 0;
				return true;
			case TokenConstType.Int:
				OutBool = Get<int>() != 0;
				return true;
			case TokenConstType.Byte:
				OutBool = Get<byte>() != 0;
				return true;
			case TokenConstType.Float:
				OutBool = Get<float>() != 0;
				return true;
			case TokenConstType.Double:
				OutBool = Get<double>() != 0;
				return true;
			case TokenConstType.Bool:
				OutBool = Get<bool>();
				return true;
			default:
				return false;
		}
	}
}

public interface IFile
{
	string FilePath { get; }
}

public interface ICodeFile : IFile
{
	string Content { get; }

	void OnNextToken(BaseParser parser, Token token);
}

public class CodeParserException : Exception
{
	private readonly string ExceptionInfo;


	private readonly string Tag;

	public CodeParserException(string tag, string exceptionInfo)
	{
		Tag = tag;
		ExceptionInfo = exceptionInfo;
	}

	public override string Message => $"[Exception] {Tag} : {ExceptionInfo}";
}

public class BaseParser
{
	protected string FileName;


	protected string Input = "";
	protected int InputLen;
	protected int InputLine;
	protected int InputPos;
	protected StringBuilder PrevComment = new();
	protected int PrevLine;
	protected int PrevPos;

	public virtual void InitParserSource(string sourceBuffer)
	{
		Input = sourceBuffer;
		InputLen = sourceBuffer.Length;
		InputPos = 0;
		InputLine = 1;
		PrevPos = 0;
		PrevLine = 1;
		FileName = "UNKNOWN";
	}

	public virtual void InitParserSource(string fileName, string sourceBuffer)
	{
		Input = sourceBuffer;
		InputLen = sourceBuffer.Length;
		InputPos = 0;
		InputLine = 1;
		PrevPos = 0;
		PrevLine = 1;
		FileName = fileName;
	}

	public virtual void ParseWithoutFile()
	{
		while (true)
		{
			var token = GetToken();
			if (token == null) break;

			CompileDeclaration(token);
		}
	}

	public virtual bool CompileDeclaration(Token token)
	{
		return true;
	}

	protected virtual bool IsBeginComment(char currentChar)
	{
		var nextChar = PeekChar();
		if (currentChar == '/' && nextChar == '*') return true;

		return false;
	}

	protected virtual bool IsEndComment(char currentChar)
	{
		var nextChar = PeekChar();
		if (currentChar == '*' && nextChar == '/') return true;

		return false;
	}

	protected virtual bool IsLineComment(char currentChar)
	{
		if (currentChar == '/' && PeekChar() == '/') return true;

		return false;
	}


	public char GetChar(bool literal = false)
	{
		var isInsideComment = false;

		PrevPos = InputPos;
		PrevLine = InputLine;

		Loop:
		if (InputPos >= Input.Length) return (char)0;

		var c = Input[InputPos++];
		if (isInsideComment) PrevComment.Append(c);

		if (c == '\n')
		{
			InputLine++;
		}
		else if (!literal)
		{
			var nextChar = PeekChar();
			if (IsBeginComment(c))
			{
				if (!isInsideComment)
				{
					ClearComment();
					PrevComment.Append(c);
					PrevComment.Append(nextChar);
					isInsideComment = true;

					// Move past the star. Do it only when not in comment,
					// otherwise end of comment might be missed e.g.
					// /*/ Comment /*/
					// ~~~~~~~~~~~~~^ Will report second /* as beginning of comment
					// And throw error that end of file is found in comment.
					InputPos++;
				}

				goto Loop;
			}

			if (IsEndComment(c))
			{
				if (!isInsideComment)
				{
					ClearComment();
					Log.Exception($"Unexpected '*/' outside of comment at {FileName} {GetLocation()}");
				}

				isInsideComment = false;

				PrevComment.Append(Input[InputPos]);

				InputPos++;
				goto Loop;
			}
		}

		if (isInsideComment)
		{
			if (c == 0)
			{
				ClearComment();
				Log.Exception($"End of class header encounted inside comment at {FileName} {GetLocation()}");
			}

			goto Loop;
		}

		return c;
	}

	public char PeekChar()
	{
		return InputPos < InputLen ? Input[InputPos] : (char)0;
	}

	public char GetLeadingChar()
	{
		var trailingCommentNewLine = (char)0;

		for (;;)
		{
			var multipleNewLines = false;
			char c;

			do
			{
				c = GetChar();

				// Check if we've encountered another newline since the last one
				if (c == trailingCommentNewLine) multipleNewLines = true;
			} while (IsWhitespace(c));

			if (!IsLineComment(c)) return c;

			if (multipleNewLines) ClearComment();

			PrevComment.Append(c);

			do
			{
				c = GetChar(true);
				if (c == 0) return c;

				PrevComment.Append(c);
			} while (!IsEOL(c));

			trailingCommentNewLine = c;

			for (;;)
			{
				c = GetChar();
				if (c == 0) return c;

				if (c == trailingCommentNewLine || !IsEOL(c))
				{
					UnGetChar();
					break;
				}

				PrevComment.Append(c);
			}
		}
	}

	public void UnGetChar()
	{
		InputPos = PrevPos;
		InputLine = PrevLine;
	}

	public static bool IsEOL(char c)
	{
		return c == '\n' || c == '\r' || c == 0;
	}

	public static bool IsWhitespace(char c)
	{
		return c == ' ' || c == '\t' || c == '\r' || c == '\n';
	}

	public void ClearComment()
	{
		PrevComment.Clear();
	}

	public Token? GetToken(bool noConst = false, bool asSingleChar = false)
	{
		var c = GetLeadingChar();
		if (c == 0)
		{
			UnGetChar();
			return null;
		}

		var token = new Token(PrevPos, PrevLine);

		var p = PeekChar();
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_')
		{
			token.Identifier.Clear();
			do
			{
				token.Identifier.Append(c);
				if (token.Identifier.Length > Token.MaxNameSize)
				{
					Log.Exception(
						$"Identifer length exceeds maximum of {Token.MaxNameSize} at {FileName} {GetLocation()}");
					break;
				}

				c = GetChar();
			} while ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_');

			UnGetChar();
			token.TokenType = TokenType.Identifier;

			if (noConst)
			{
				if (token.Matches("true"))
				{
					token.SetConstBool(true);
					return token;
				}

				if (token.Matches("false"))
				{
					token.SetConstBool(false);
					return token;
				}
			}

			return token;
		}

		if (!noConst && ((c >= '0' && c <= '9') || ((c == '+' || c == '-') && p >= '0' && p <= '9')))
		{
			var isFloat = false;
			var isHex = false;
			token.Identifier.Clear();

			do
			{
				if (c == '.') isFloat = true;

				if (c == 'X' || c == 'x') isHex = true;

				token.Identifier.Append(c);
				if (token.Identifier.Length >= Token.MaxNameSize)
				{
					Log.Exception(
						$"Number length exceeds maximum of {Token.MaxNameSize} at {FileName} {GetLocation()}");
					break;
				}

				c = char.ToUpper(GetChar());
			} while ((c >= '0' && c <= '9') || (!isFloat && c == '.') || (!isHex && c == 'X') ||
			         (isHex && c >= 'A' && c <= 'F'));

			if (!isFloat || c != 'F') UnGetChar();

			if (isFloat)
			{
				if (float.TryParse(token.Identifier.ToString(), out var result))
					token.SetConstFloat(result);
				else
					Log.Exception($"cannot parse {token.Identifier} to float at {FileName} {GetLocation()}");
			}
			else if (isHex)
			{
				if (long.TryParse(token.Identifier.ToString().Substring(2), NumberStyles.HexNumber, null,
					    out var result))
					token.SetInt64(result);
				else
					Log.Exception($"cannot parse {token.Identifier} to hex long at {FileName} {GetLocation()}");
			}
			else
			{
				if (long.TryParse(token.Identifier.ToString(), out var result))
					token.SetInt64(result);
				else
					Log.Exception($"cannot parse {token.Identifier} to long at {FileName} {GetLocation()}");
			}

			return token;
		}

		if (c == '\'')
		{
			var actualCharLiteral = GetChar(true);

			if (actualCharLiteral == '\\')
			{
				actualCharLiteral = GetChar(true);
				switch (actualCharLiteral)
				{
					case 't':
						actualCharLiteral = '\t';
						break;
					case 'n':
						actualCharLiteral = '\n';
						break;
					case 'r':
						actualCharLiteral = '\r';
						break;
				}
			}

			c = GetChar(true);

			if (c != '\'')
			{
				Log.Exception($"Unterminated character constant at {FileName} {GetLocation()}");
				UnGetChar();
			}

			token.SetConstChar(actualCharLiteral);
			return token;
		}

		if (c == '"')
		{
			var temp = new StringBuilder();
			c = GetChar(true);
			while (c != '"' && !IsEOL(c))
			{
				if (c == '\\')
				{
					c = GetChar(true);
					if (IsEOL(c))
						break;
					if (c == 'n') c = '\n';
				}

				temp.Append(c);
				if (temp.Length >= Token.MaxStringConstLength)
				{
					Log.Exception(
						$"String constant exceeds maximum of {Token.MaxStringConstLength} characters at {FileName} {GetLocation()}");
					temp.Append('\"');
					break;
				}

				c = GetChar(true);
			}

			if (c != '"')
			{
				Log.Exception($"Unterminated string constant : {temp} at {FileName} {GetLocation()}");
				UnGetChar();
			}

			token.SetConstString(temp.ToString());
			return token;
		}

		token.Identifier.Clear();
		token.Identifier.Append(c);

		var d = GetChar();

		bool IsPair(char cc, char dd)
		{
			return c == cc && d == dd && !asSingleChar;
		}

		if (IsPair('<', '<')
		    || IsPair('>', '>')
		    || IsPair('!', '=')
		    || IsPair('<', '=')
		    || IsPair('>', '=')
		    || IsPair('+', '+')
		    || IsPair('-', '-')
		    || IsPair('+', '=')
		    || IsPair('-', '=')
		    || IsPair('*', '=')
		    || IsPair('/', '=')
		    || IsPair('&', '&')
		    || IsPair('|', '|')
		    || IsPair('^', '^')
		    || IsPair('=', '=')
		    || IsPair('*', '*')
		    || IsPair('~', '=')
		    || IsPair(':', ':')
		   )
		{
			token.Identifier.Append(d);
			if (c == '>' && d == '>')
			{
				if (GetChar() == '>')
					token.Identifier.Append('>');
				else
					UnGetChar();
			}
		}
		else
		{
			UnGetChar();
		}

		token.TokenType = TokenType.Symbol;

		return token;
	}

	public List<Token> GetTokensUntil(Func<Token, bool> condition, bool noConst = false, string debugMessage = "")
	{
		var tokens = new List<Token>();
		while (true)
		{
			var currentToken = GetToken(noConst)
			                   ?? throw new CodeParserException("Cpp Parser",
				                   $"exit early !! {debugMessage} at {FileName} {GetLocation()}");

			tokens.Add(currentToken);
			if (condition(currentToken)) break;
		}

		return tokens;
	}

	public List<Token> GetTokensUntilMatch(char match, bool noConst = false, string debugMessage = "")
	{
		var tokens = new List<Token>();
		while (true)
		{
			var currentToken = GetToken(noConst)
			                   ?? throw new CodeParserException("Cpp Parser",
				                   $"exit early !! {debugMessage} at {FileName} {GetLocation()}");

			tokens.Add(currentToken);
			if (currentToken.Matches(match)) break;
		}

		return tokens;
	}

	public List<Token> GetTokensUntilMatch(string match, bool noConst = false, string debugMessage = "")
	{
		var tokens = new List<Token>();
		while (true)
		{
			var currentToken = GetToken(noConst)
			                   ?? throw new CodeParserException("Cpp Parser",
				                   $"exit early !! {debugMessage} at {FileName} {GetLocation()}");

			tokens.Add(currentToken);

			if (currentToken.Matches(match)) break;
		}

		return tokens;
	}

	public List<Token> GetTokensUntilPairMatch(char left, char right, string debugMessage = "")
	{
		var matchCount = 1;
		var tokens = new List<Token>();
		while (true)
		{
			var currentToken = GetToken()
			                   ?? throw new CodeParserException("Cpp Parser",
				                   $"exit early !! {debugMessage} at {FileName} {GetLocation()}");

			tokens.Add(currentToken);

			if (currentToken.Matches(left))
				matchCount++;
			else if (currentToken.Matches(right)) matchCount--;

			if (matchCount == 0) break;
		}

		return tokens;
	}

	public void UnGetToken(Token token)
	{
		InputPos = token.StartPos;
		InputLine = token.StartLine;
	}

	public Token? GetIdentifier(bool noConst = false)
	{
		var token = GetToken(noConst);
		if (token == null) return null;

		if (token.TokenType == TokenType.Identifier) return token;

		UnGetToken(token);
		return null;
	}

	public Token? GetSymbol()
	{
		var token = GetToken();
		if (token == null) return null;

		if (token.TokenType == TokenType.Symbol) return token;

		UnGetToken(token);
		return null;
	}

	public bool GetConstInt(out int result, string tag = "")
	{
		result = 0;
		var token = GetToken();
		if (token != null)
		{
			if (token.GetConstInt(out result))
				return true;
			UnGetToken(token);
		}

		if (string.IsNullOrEmpty(tag)) Log.Exception($"{tag} : Missing constant integer at {FileName} {GetLocation()}");

		return false;
	}

	public bool GetConstInt64(out long result, string tag = "")
	{
		result = 0;
		var token = GetToken();
		if (token != null)
		{
			if (token.GetConstInt64(out result))
				return true;
			UnGetToken(token);
		}

		if (string.IsNullOrEmpty(tag)) Log.Exception($"{tag} : Missing constant integer at {FileName} {GetLocation()}");

		return false;
	}

	public bool MatchIdentifier(string match)
	{
		var token = GetToken();
		if (token != null)
		{
			if (token.TokenType == TokenType.Identifier
			    && token.Matches(match))
				return true;
			UnGetToken(token);
		}

		return false;
	}

	public bool MatchConstInt(string match)
	{
		var token = GetToken();
		if (token != null)
		{
			if (token.TokenType == TokenType.Const
			    && (token.ConstType == TokenConstType.Int || token.ConstType == TokenConstType.Int64)
			    && token.GetTokenName() == match)
				return true;
			UnGetToken(token);
		}

		return false;
	}


	private bool MatchAnyConstInt()
	{
		var token = GetToken();
		if (token != null)
		{
			if (token.TokenType == TokenType.Const
			    && (token.ConstType == TokenConstType.Int || token.ConstType == TokenConstType.Int64))
				return true;
			UnGetToken(token);
		}

		return false;
	}

	public bool PeekIdentifier(string match)
	{
		var token = GetToken(true);
		if (token == null) return false;
		UnGetToken(token);
		return token.TokenType == TokenType.Identifier
		       && token.GetTokenName() == match;
	}

	public bool MatchSymbol(char match)
	{
		var token = GetToken(true, true);
		if (token != null)
		{
			if (token.TokenType == TokenType.Symbol
			    && token.Identifier[0] == match && token.Identifier.Length == 1)
				return true;
			UnGetToken(token);
		}

		return false;
	}

	public bool MatchSymbol(string match)
	{
		var token = GetToken(true);
		if (token != null)
		{
			if (token.TokenType == TokenType.Symbol
			    && token.Identifier.ToString() == match)
				return true;
			UnGetToken(token);
		}

		return false;
	}

	public bool MatchToken(Func<Token, bool> condition)
	{
		var token = GetToken(true);
		if (token != null)
		{
			if (condition(token))
				return true;
			UnGetToken(token);
		}

		return false;
	}

	public bool MatchSemi()
	{
		if (MatchSymbol(';')) return true;
		return false;
	}

	public bool PeekSymbol(char match)
	{
		var token = GetToken(true);
		if (token == null) return false;
		UnGetToken(token);
		return token.TokenType == TokenType.Symbol
		       && token.Identifier[0] == match
		       && token.Identifier.Length == 1;
	}

	public void RequireIdentifier(string match, string tag)
	{
		Debug.Assert(MatchIdentifier(match), "Cpp Parse", $"missing '{match}' in {tag}");
	}

	public void RequireSymbol(char match, string tag)
	{
		Debug.Assert(MatchSymbol(match), "Cpp Parse", $"missing '{match}' in {tag}");
	}

	public void RequireSymbol(char match, Func<string> tagGetter)
	{
		Debug.Assert(MatchSymbol(match), "Cpp Parse", $"missing '{match}' in {tagGetter()}");
	}

	public void RequireConstInt(string match, string tag)
	{
		Debug.Assert(MatchConstInt(match), "Cpp Parse", $"missing '{match}' in {tag}");
	}

	public void RequireAnyConstInt(string tag)
	{
		Debug.Assert(MatchAnyConstInt(), "Cpp Parse", $"missing integer in {tag}");
	}

	public void RequireSemi()
	{
		if (!MatchSymbol(';'))
		{
			var token = GetToken();
			if (token != null)
				Log.Exception($"Missing ';' before {token.Identifier} at location {GetLocation()}");
			else
				Log.Exception($"Missing ';' at {FileName} {GetLocation()}");
		}
	}

	public string GetLocation()
	{
		return $"line:{InputLine} pos:{InputPos}";
	}
}

public class BaseParserWithFile : BaseParser
{
	public void Parse(ICodeFile file)
	{
		PreParserProcess(file);

		while (true)
		{
			var token = GetToken();
			if (token == null) break;

			file.OnNextToken(this, token);

			CompileDeclaration(file, token);
		}

		PostParserProcess(file);
	}

	public virtual void PreParserProcess(ICodeFile file)
	{
	}

	public virtual void PostParserProcess(ICodeFile file)
	{
	}

	public string GetFileLocation(ICodeFile? file)
	{
		return $"file : {file?.FilePath ?? "UNKNOWN"} position : {GetLocation()}";
	}

	public virtual bool CompileDeclaration(Token token)
	{
		return CompileDeclaration(null, token);
	}

	public virtual bool CompileDeclaration(ICodeFile? file, Token token)
	{
		return true;
	}
}

public class IniFile : ICodeFile
{
	private IniFile(string filePath)
	{
		FilePath = filePath;
		Content = File.ReadAllText(filePath);
	}

	public Dictionary<string, Section> Sections { get; } = new();
	public string FilePath { get; }
	public string Content { get; }

	public void OnNextToken(BaseParser parser, Token token)
	{
	}

	public static IniFile Parser(string filePath)
	{
		var iniFile = new IniFile(filePath);
		var parser = new IniFileParser();
		parser.InitParserSource(iniFile.FilePath, iniFile.Content);
		parser.Parse(iniFile);
		return iniFile;
	}

	public class Section
	{
		public Section(string name)
		{
			Name = name;
			Properties = new Dictionary<string, SectionItem>();
		}

		public string Name { get; }
		public Dictionary<string, SectionItem> Properties { get; }
	}

	public class SectionItem
	{
		public enum SectionItemType
		{
			String,
			Single,
			List,
			Map
		}

		private SectionItem(SectionItemType type, object item)
		{
			ItemType = type;
			Item = item;
		}

		public SectionItemType ItemType { get; }
		public object Item { get; }
		public string Str => Item as string ?? throw new Exception("not a string !!");
		public Ref<SectionItem> Single => Item as Ref<SectionItem> ?? throw new Exception("not a single !!");
		public List<SectionItem> List => Item as List<SectionItem> ?? throw new Exception("not a list !!");

		public Dictionary<string, SectionItem> Map =>
			Item as Dictionary<string, SectionItem> ?? throw new Exception("not a map !!");

		public static SectionItem CreateString(string content)
		{
			return new SectionItem(SectionItemType.String, content);
		}

		public static SectionItem CreateSingle()
		{
			return new SectionItem(SectionItemType.Single, new Ref<SectionItem>());
		}

		public static SectionItem CreateList()
		{
			return new SectionItem(SectionItemType.List, new List<SectionItem>());
		}

		public static SectionItem CreateMap()
		{
			return new SectionItem(SectionItemType.Map, new Dictionary<string, SectionItem>());
		}

		public class Ref<T> where T : class
		{
			public T? Value;
		}
	}
}

public class IniFileParser : BaseParserWithFile
{
	private Stack<IIniScope> ScopeStack { get; } = new();

	public override void PreParserProcess(ICodeFile file)
	{
		var iniFile = file as IniFile ?? throw new CodeParserException("IniParse", "Invalid file type !!");
		ScopeStack.Push(new FileScope(iniFile));
	}

	public override void PostParserProcess(ICodeFile file)
	{
		Debug.Assert(ScopeStack.Count == 2 && ScopeStack.Peek() is SectionScope);
		ScopeStack.Pop();

		Debug.Assert(ScopeStack.Count == 1 && ScopeStack.Peek() is FileScope);
		ScopeStack.Pop();
	}

	public override bool CompileDeclaration(ICodeFile? file, Token token)
	{
		var currentScope = ScopeStack.Peek();
		if (currentScope is FileScope fileScope)
			return CompileFileScope(file, fileScope, token);
		if (currentScope is SectionScope sectionScope)
			return CompileSectionScope(file, sectionScope, token);
		if (currentScope is SectionItemScope sectionItemScope)
			return CompileSectionItemScope(file, sectionItemScope, token);
		throw new CodeParserException("Ini Parse", $"unexpected scope {GetFileLocation(file)}");
	}

	private bool CompileFileScope(ICodeFile? file, FileScope fileScope, Token token)
	{
		Debug.Assert(token.Matches('['));
		var builder = new StringBuilder();
		while (true)
		{
			var nameToken = GetToken(true) ??
			                throw new CodeParserException("Ini Parse",
				                $"unexpected end of file {GetFileLocation(file)}");
			if (nameToken.Matches(']'))
			{
				Debug.Assert(builder.Length > 0);
				break;
			}

			builder.Append(nameToken.GetTokenName());
		}

		var name = builder.ToString();
		var newSection = new IniFile.Section(name);
		fileScope.File.Sections.Add(name, newSection);

		ScopeStack.Push(new SectionScope(newSection));

		return true;
	}

	private bool CompileSectionScope(ICodeFile? file, SectionScope sectionScope, Token token)
	{
		var isList = token.Matches('+');
		var sectionNameBuilder = new StringBuilder();
		var sectionItemNameToken =
			(isList ? GetToken(true) : token) ??
			throw new CodeParserException("Ini Parse", $"unexpected end of file {GetFileLocation(file)}");
		while (!sectionItemNameToken.Matches('='))
		{
			Debug.Assert(sectionItemNameToken.TokenType != TokenType.Const);
			sectionNameBuilder.Append(sectionItemNameToken.GetTokenName());
			sectionItemNameToken = GetToken(true) ??
			                       throw new CodeParserException("Ini Parse",
				                       $"unexpected end of file {GetFileLocation(file)}");
		}

		var sectionItemNameStr = sectionNameBuilder.ToString();

		IniFile.SectionItem item;
		if (isList)
		{
			if (!sectionScope.Section.Properties.TryGetValue(sectionItemNameStr, out item))
			{
				item = IniFile.SectionItem.CreateList();
				sectionScope.Section.Properties.Add(sectionItemNameStr, item);
			}
		}
		else
		{
			Debug.Assert(!sectionScope.Section.Properties.ContainsKey(sectionItemNameStr));
			item = IniFile.SectionItem.CreateSingle();
			sectionScope.Section.Properties.Add(sectionItemNameStr, item);
		}

		ScopeStack.Push(new SectionItemScope(item));
		return true;
	}

	private bool CompileSectionItemScope(ICodeFile? file, SectionItemScope sectionItemScope, Token token)
	{
		var item = sectionItemScope.Item;
		Debug.Assert(item.ItemType != IniFile.SectionItem.SectionItemType.String);

		if (item.ItemType == IniFile.SectionItem.SectionItemType.Single)
		{
			item.Single.Value = ParseValue(file, token);
			ScopeStack.Pop();
			return true;
		}

		if (item.ItemType == IniFile.SectionItem.SectionItemType.List)
		{
			item.List.Add(ParseValue(file, token));
			ScopeStack.Pop();
			return true;
		}

		if (item.ItemType == IniFile.SectionItem.SectionItemType.Map)
		{
			if (token.TokenType != TokenType.Identifier)
				throw new CodeParserException("Ini Parse", $"must start with a identify : {GetFileLocation(file)}");

			var name = token.GetTokenName();
			RequireSymbol('=', "Ini Parse");
			item.Map.Add(name, ParseValue(file, token));
			ScopeStack.Pop();
			return true;
		}

		throw new CodeParserException("Ini Parse", $"unexpected item type :{item.ItemType} at {GetFileLocation(file)}");
	}

	private IniFile.SectionItem ParseValue(ICodeFile? file, Token token)
	{
		IniFile.SectionItem newItem;
		if (token.Matches('('))
		{
			UnGetToken(token);
			newItem = IniFile.SectionItem.CreateMap();
			ScopeStack.Push(new SectionItemScope(newItem));
			ParseMap(file);
		}
		else if (token.Matches('['))
		{
			UnGetToken(token);
			newItem = IniFile.SectionItem.CreateList();
			ScopeStack.Push(new SectionItemScope(newItem));
			ParseList(file);
		}
		else
		{
			var itemContentToken = token;
			var itemContentBuilder = new StringBuilder();
			if (token.TokenType == TokenType.Identifier || token.TokenType == TokenType.Symbol)
			{
				itemContentBuilder.Append(itemContentToken.GetTokenName());
				while (!itemContentToken.Matches(')') && itemContentToken.Matches(']') && itemContentToken.Matches(','))
				{
					Debug.Assert(itemContentToken.TokenType == TokenType.Identifier);
					itemContentToken = GetToken(true) ?? throw new CodeParserException("Ini Parse",
						$"unexpected end of file {GetFileLocation(file)}");
					itemContentBuilder.Append(itemContentToken.GetTokenName());
				}
			}
			else if (token.TokenType == TokenType.Const)
			{
				itemContentBuilder.Append(itemContentToken.GetTokenName());
			}
			else
			{
				throw new CodeParserException("Ini parse", $"unexpected token type {GetFileLocation(file)}");
			}

			newItem = IniFile.SectionItem.CreateString(itemContentBuilder.ToString());
		}

		return newItem;
	}

	private bool ParseMap(ICodeFile? file)
	{
		MatchSymbol('(');
		var mapItem = ScopeStack.Peek() as SectionItemScope
		              ?? throw new CodeParserException("Ini Parse",
			              $"unexpected scope, expect SectionItemScope {GetFileLocation(file)}");
		while (true)
		{
			var token = GetToken();

			if (token == null)
				throw new CodeParserException("Ini Parse", $"unexpected end of file :{GetFileLocation(file)}");

			if (token.Matches(')'))
			{
				ScopeStack.Pop();
				break;
			}

			if (token.Matches(',')) continue;

			var mapItemNameToken = token;
			var mapItemNameBuilder = new StringBuilder();
			while (!mapItemNameToken.Matches('='))
			{
				Debug.Assert(mapItemNameToken.TokenType != TokenType.Const);
				mapItemNameBuilder.Append(mapItemNameToken.GetTokenName());
				mapItemNameToken = GetToken(true) ??
				                   throw new CodeParserException("Ini Parse",
					                   $"unexpected end of file {GetFileLocation(file)}");
			}

			var nextToken = GetToken() ??
			                throw new CodeParserException("Ini Parse",
				                $"unexpected end of file {GetFileLocation(file)}");
			var subItem = ParseValue(file, nextToken);
			mapItem.Item.Map.Add(mapItemNameBuilder.ToString(), subItem);
		}

		return true;
	}

	private bool ParseList(ICodeFile? file)
	{
		MatchSymbol('[');
		var listItem = ScopeStack.Peek() as SectionItemScope
		               ?? throw new CodeParserException("Ini Parse",
			               $"unexpected scope, expect SectionItemScope {GetFileLocation(file)}");
		while (true)
		{
			var token = GetToken();

			if (token == null)
				throw new CodeParserException("Ini Parse", $"unexpected end of file :{GetFileLocation(file)}");

			if (token.Matches(']'))
			{
				ScopeStack.Pop();
				break;
			}

			if (token.Matches(',')) continue;

			var subItem = ParseValue(file, token);
			listItem.Item.List.Add(subItem);
		}

		return true;
	}


	protected override bool IsBeginComment(char currentChar)
	{
		return false;
	}

	protected override bool IsEndComment(char currentChar)
	{
		return false;
	}

	protected override bool IsLineComment(char currentChar)
	{
		return currentChar == '#' || currentChar == ';';
	}

	private interface IIniScope
	{
	}

	private class FileScope : IIniScope
	{
		public FileScope(IniFile file)
		{
			File = file;
		}

		public IniFile File { get; }
	}

	private class SectionScope : IIniScope
	{
		public SectionScope(IniFile.Section section)
		{
			Section = section;
		}

		public IniFile.Section Section { get; }
	}

	private class SectionItemScope : IIniScope
	{
		public SectionItemScope(IniFile.SectionItem item)
		{
			Item = item;
		}

		public IniFile.SectionItem Item { get; }
	}
}

public class Log
{
	public static void Exception(string info)
	{
		throw new Exception(info);
	}
}