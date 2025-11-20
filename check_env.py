try:
    import volatility3
    print("Volatility3: OK")
except ImportError:
    print("Volatility3: MISSING")

try:
    import openai
    print("OpenAI: OK")
except ImportError:
    print("OpenAI: MISSING")

try:
    import rich
    print("Rich: OK")
except ImportError:
    print("Rich: MISSING")
