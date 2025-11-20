import os
import json
import subprocess
import sys
import re
from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.prompt import Confirm, Prompt
from rich.panel import Panel
from openai import OpenAI

# Initialize Rich Console
from rich.text import Text

# Initialize Rich Console
console = Console()

class LLMClient:
    def __init__(self, provider: str, api_key: str = None, base_url: str = None, model: str = None):
        self.provider = provider
        self.model = model
        
        if provider == "openai":
            self.client = OpenAI(api_key=api_key)
            self.model = model or "gpt-4o"
        elif provider == "ollama":
            # Ollama is compatible with OpenAI client if we point to local base_url
            self.client = OpenAI(
                base_url=base_url or "http://localhost:11434/v1",
                api_key="ollama", # required but ignored
            )
            self.model = model or "llama3" # default to llama3 if not specified
            
    def create_completion(self, system_prompt: str, user_prompt: str) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            console.print(f"[bold red]LLM Error ({self.provider}): {e}[/bold red]")
            if self.provider == "ollama":
                console.print("[yellow]Tip: Ensure Ollama is running (e.g., 'ollama serve') and the model is pulled (e.g., 'ollama pull llama3')[/yellow]")
            return ""

class Executor:
    def __init__(self, image_path: str):
        self.image_path = image_path
        self.vol_script = os.path.join(os.path.dirname(__file__), "volatility3", "vol.py")

    def get_available_plugins(self) -> List[str]:
        """
        Runs vol.py --help to get a list of available plugins.
        """
        if not os.path.exists(self.vol_script):
            return []
            
        cmd = [sys.executable, self.vol_script, "-f", self.image_path, "--help"]
        try:
            # This might take a moment as it scans for plugins
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            output = result.stdout + result.stderr
            
            # Parse plugins from the output. 
            # Volatility 3 help lists plugins usually in a section. 
            # A simple regex to find words starting with 'windows.', 'linux.', 'mac.' might work.
            plugins = re.findall(r'(windows\.[a-zA-Z0-9_]+|linux\.[a-zA-Z0-9_]+|mac\.[a-zA-Z0-9_]+)', output)
            return sorted(list(set(plugins)))
        except Exception:
            return []

    def execute_plugin(self, plugin_name: str) -> str:
        """
        Executes a Volatility 3 plugin and returns the output.
        """
        console.print(f"[bold yellow]Running plugin: {plugin_name}...[/bold yellow]")
        
        if not os.path.exists(self.vol_script):
             console.print(f"[bold red]Error: vol.py not found at {self.vol_script}[/bold red]")
             return "Error: Volatility 3 script not found."

        cmd = [sys.executable, self.vol_script, "-f", self.image_path, plugin_name]
        
        try:
            # Capture stdout and stderr
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if result.returncode != 0:
                console.print(f"[bold red]Plugin {plugin_name} failed![/bold red]")
                # console.print(f"Error: {result.stderr}") # Reduce noise
                return f"Error running {plugin_name}: {result.stderr}"
            
            return result.stdout
        except Exception as e:
            return f"Execution exception: {str(e)}"

class Planner:
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client

    def create_plan(self, scenario: str, available_plugins: List[str]) -> List[Dict[str, str]]:
        """
        Generates a list of Volatility 3 plugins to run based on the user scenario.
        """
        console.print(f"[bold blue]Thinking ({self.llm.provider})... Generating investigation plan...[/bold blue]")
        
        # Filter plugins to keep prompt size manageable, or just provide the full list if not too huge.
        # For now, let's provide the full list but formatted nicely.
        plugin_list_str = ", ".join(available_plugins)
        
        prompt = f"""
        You are an expert digital forensics investigator using Volatility 3.
        
        User Scenario: "{scenario}"
        
        AVAILABLE PLUGINS:
        [{plugin_list_str}]
        
        Based on this scenario, select the most relevant Volatility 3 plugins from the AVAILABLE PLUGINS list above.
        DO NOT invent new plugins. Use ONLY the ones listed.
        
        Return ONLY a JSON array of objects, where each object has:
        - "plugin": The exact plugin name from the list.
        - "reason": A brief explanation of why this plugin is relevant.
        
        Order the plugins logically.
        """
        
        content = self.llm.create_completion("You are a helpful forensic assistant.", prompt)
        
        if not content:
            return []

        try:
            # Use regex to find the JSON array
            match = re.search(r'\[.*\]', content, re.DOTALL)
            if match:
                json_str = match.group(0)
                plan = json.loads(json_str)
            else:
                # Fallback to original cleaning if regex fails (unlikely but safe)
                if content.startswith("```json"):
                    content = content[7:]
                if content.startswith("```"):
                    content = content[3:]
                if content.endswith("```"):
                    content = content[:-3]
                plan = json.loads(content.strip())
            
            # Validate plan against available plugins
            valid_plan = []
            for step in plan:
                if step['plugin'] in available_plugins:
                    valid_plan.append(step)
                else:
                    console.print(f"[yellow]Warning: LLM suggested invalid plugin '{step['plugin']}'. Skipping.[/yellow]")
            
            return valid_plan
        except json.JSONDecodeError:
            console.print(f"[bold red]Error parsing plan JSON from LLM. Raw output:[/bold red]\n{content}")
            return []
        except Exception as e:
            console.print(f"[bold red]Error generating plan: {e}[/bold red]")
            return []

class Analyst:
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client

    def analyze_output(self, plugin_name: str, output: str, scenario: str) -> str:
        """
        Analyzes the raw output of a plugin in the context of the scenario.
        """
        console.print(f"[bold blue]Analyzing output for {plugin_name} ({self.llm.provider})...[/bold blue]")
        
        # Truncate output if it's too long for the context window
        max_len = 50000 
        if len(output) > max_len:
            output = output[:max_len] + "\n...[Output Truncated]..."

        prompt = f"""
        You are a forensic analyst.
        
        Scenario: "{scenario}"
        Plugin Run: "{plugin_name}"
        
        Output:
        {output}
        
        Analyze this output. 
        1. Identify any suspicious entries related to the scenario.
        2. Explain what they mean.
        3. If nothing suspicious is found, state that clearly.
        
        Keep your analysis concise and factual.
        """
        
        return self.llm.create_completion("You are a sharp-eyed forensic analyst.", prompt)

class Reporter:
    def generate_report(self, scenario: str, findings: List[Dict[str, Any]]) -> str:
        """
        Generates an interactive HTML report with Mermaid diagrams.
        """
        console.print("[bold green]Generating final report...[/bold green]")
        
        # Generate Mermaid Graph for the flow
        graph_nodes = ["Start[Start Investigation]"]
        for i, item in enumerate(findings):
            plugin = item['plugin']
            node_id = f"Step{i}"
            graph_nodes.append(f"{node_id}[Run {plugin}]")
        
        graph_edges = []
        for i in range(len(graph_nodes) - 1):
            graph_edges.append(f"{graph_nodes[i].split('[')[0]} --> {graph_nodes[i+1].split('[')[0]}")
        graph_edges.append(f"{graph_nodes[-1].split('[')[0]} --> End[Report Generated]")
        
        mermaid_graph = "graph TD;\n" + ";\n".join(graph_edges) + ";"

        report_html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Forensic Investigation Report</title>
            <style>
                :root {{
                    --primary-color: #2c3e50;
                    --secondary-color: #3498db;
                    --accent-color: #e67e22;
                    --bg-color: #f4f6f7;
                    --text-color: #333;
                }}
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: var(--bg-color); color: var(--text-color); }}
                .container {{ max-width: 1000px; margin: 40px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                h1 {{ color: var(--primary-color); border-bottom: 2px solid var(--secondary-color); padding-bottom: 10px; }}
                h2 {{ color: var(--primary-color); margin-top: 30px; }}
                .scenario-box {{ background: #e8f6f3; padding: 20px; border-left: 5px solid #1abc9c; margin-bottom: 30px; }}
                .finding {{ border: 1px solid #ddd; margin-bottom: 20px; border-radius: 5px; overflow: hidden; }}
                .finding-header {{ background: #ecf0f1; padding: 15px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }}
                .finding-header:hover {{ background: #e0e6e8; }}
                .finding-header h3 {{ margin: 0; color: var(--primary-color); font-size: 1.1em; }}
                .finding-content {{ padding: 20px; display: none; }}
                .finding-content.active {{ display: block; }}
                .badge {{ background: var(--accent-color); color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }}
                .analysis-box {{ background: #fdf2e9; padding: 15px; border-left: 4px solid var(--accent-color); margin-bottom: 15px; }}
                pre {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Consolas', monospace; font-size: 0.9em; }}
                .toggle-icon {{ font-weight: bold; transition: transform 0.3s; }}
                .active .toggle-icon {{ transform: rotate(180deg); }}
            </style>
            <script type="module">
                import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
                mermaid.initialize({{ startOnLoad: true }});
            </script>
        </head>
        <body>
            <div class="container">
                <h1>Forensic Investigation Report</h1>
                
                <div class="scenario-box">
                    <strong>Scenario:</strong> {scenario}
                </div>
                
                <h2>Investigation Flow</h2>
                <div class="mermaid">
                {mermaid_graph}
                </div>
                
                <h2>Detailed Findings</h2>
                <p>Click on each step to view details.</p>
        """
        
        for i, item in enumerate(findings):
            plugin = item['plugin']
            analysis = item['analysis']
            raw_output = item['raw_output']
            # Escape HTML in raw output
            raw_output_safe = raw_output.replace("<", "&lt;").replace(">", "&gt;")
            analysis_safe = analysis.replace("\n", "<br>")
            
            report_html += f"""
            <div class="finding">
                <div class="finding-header" onclick="this.nextElementSibling.classList.toggle('active'); this.querySelector('.toggle-icon').innerText = this.nextElementSibling.classList.contains('active') ? '\\u25BC' : '\\u25B6';">
                    <h3>Step {i+1}: {plugin}</h3>
                    <span class="toggle-icon">&#9654;</span>
                </div>
                <div class="finding-content">
                    <div class="analysis-box">
                        <strong>AI Analysis:</strong><br>
                        {analysis_safe}
                    </div>
                    <details>
                        <summary>View Raw Output</summary>
                        <pre>{raw_output_safe}</pre>
                    </details>
                </div>
            </div>
            """
            
        report_html += """
            </div>
        </body>
        </html>
        """
        return report_html

class Investigator:
    def __init__(self):
        self.show_welcome()
        self.setup_llm()
        self.planner = Planner(self.llm_client)
        self.analyst = Analyst(self.llm_client)
        self.reporter = Reporter()
        self.findings = []

    def show_welcome(self):
        batman_art = r"""
       _==/          i     i          \==_
     /XX/            |\___/|            \XX\
   /XXXX\            |XXXXX|            /XXXX\
  |XXXXXX\_         _XXXXXXX_         _/XXXXXX|
 XXXXXXXXXXXxxxxxxxXXXXXXXXXXXxxxxxxxXXXXXXXXXXX
|XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX|
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
|XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX|
 XXXXXX/^^^^"\XXXXXXXXXXXXXXXXXXXXX/^^^^^\XXXXXX
  |XXX|       \XXX/^^\XXXXX/^^\XXX/       |XXX|
    \XX\       \X/    \XXX/    \X/       /XX/
       "\       "      \X/      "      /"
        """
        
        console.print("[bold black on yellow]  THE DARK KNIGHT INVESTIGATOR  [/bold black on yellow]", justify="center")
        
        # Simple animation effect
        import time
        for line in batman_art.split("\n"):
            # Use Text object to avoid markup parsing issues with backslashes
            text = Text(line, style="bold grey30")
            console.print(text, justify="center")
            time.sleep(0.05)
            
        console.print("\n[bold cyan]\"It's not who I am underneath, but what I do that defines me.\"[/bold cyan]", justify="center")
        console.print("[italic]...initializing forensic protocols...[/italic]\n", justify="center")
        time.sleep(1)

    def setup_llm(self):
        console.print(Panel.fit(
            "[bold cyan]Agentic Forensic Investigator[/bold cyan]\n"
            "[italic]Created by Ishan Perera[/italic]\n\n"
            "Choose your AI Brain:\n"
            "1. [bold green]Cloud (OpenAI)[/bold green]: Smartest, Faster, Requires API Key & Internet.\n"
            "2. [bold yellow]Local (Ollama)[/bold yellow]: Private, Offline, Requires Local Model (e.g., Llama 3).",
            title="Welcome"
        ))
        
        choice = Prompt.ask("Select Option", choices=["1", "2"], default="1")
        
        if choice == "1":
            api_key = os.environ.get("OPENAI_API_KEY")
            if not api_key:
                console.print("\n[yellow]To use OpenAI, you need an API Key.[/yellow]")
                console.print("[yellow]Get one here: https://platform.openai.com/api-keys[/yellow]")
                api_key = Prompt.ask("Enter your OpenAI API Key (input will be hidden)", password=True)
            self.llm_client = LLMClient("openai", api_key=api_key)
            console.print("[green]Using OpenAI (Cloud)[/green]")
            
        else:
            base_url = Prompt.ask("Enter Ollama URL", default="http://localhost:11434/v1")
            # Ensure URL ends with /v1 for OpenAI compatibility
            if not base_url.endswith("/v1") and not base_url.endswith("/v1/"):
                base_url = base_url.rstrip("/") + "/v1"
            
            model = Prompt.ask("Enter Model Name", default="llama3")
            self.llm_client = LLMClient("ollama", base_url=base_url, model=model)
            console.print(f"[yellow]Using Ollama (Local) - Model: {model}[/yellow]")

    def run(self):
        # 1. Get Image Path
        image_path = console.input("Enter the path to the memory image file: ").strip()
        if not os.path.exists(image_path):
            console.print("[bold red]File not found![/bold red]")
            return

        self.executor = Executor(image_path)
        
        # 1.5 Pre-fetch plugins
        console.print("[bold blue]Scanning for available plugins...[/bold blue]")
        available_plugins = self.executor.get_available_plugins()
        if not available_plugins:
            console.print("[bold red]Could not list plugins. Is Volatility 3 working?[/bold red]")
            # Continue anyway, maybe list was empty but execution might work? Unlikely.
            # But let's not crash.
        else:
            console.print(f"[green]Found {len(available_plugins)} plugins.[/green]")

        # 2. Get Scenario
        scenario = console.input("Describe the scenario/incident (e.g., 'Suspicious network activity detected'): ").strip()
        
        # 3. Plan
        plan = self.planner.create_plan(scenario, available_plugins)
        if not plan:
            console.print("[red]No valid plan could be generated.[/red]")
            return

        # Display Plan
        table = Table(title="Proposed Investigation Plan")
        table.add_column("Step", style="cyan")
        table.add_column("Plugin", style="magenta")
        table.add_column("Reason", style="green")
        
        for i, step in enumerate(plan):
            table.add_row(str(i+1), step['plugin'], step['reason'])
            
        console.print(table)
        
        if not Confirm.ask("Do you want to proceed with this plan?"):
            console.print("Investigation aborted.")
            return

        # 4. Execute & Analyze
        for step in plan:
            plugin = step['plugin']
            
            # Execute
            raw_output = self.executor.execute_plugin(plugin)
            
            # Analyze
            analysis = self.analyst.analyze_output(plugin, raw_output, scenario)
            
            # Store
            self.findings.append({
                "plugin": plugin,
                "raw_output": raw_output,
                "analysis": analysis
            })
            
            console.print(f"[green]Analysis for {plugin} complete.[/green]")
            console.print("-" * 40)

        # 5. Report
        report_content = self.reporter.generate_report(scenario, self.findings)
        report_file = "investigation_report.html"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report_content)
            
        console.print(f"[bold green]Report generated: {os.path.abspath(report_file)}[/bold green]")

if __name__ == "__main__":
    try:
        agent = Investigator()
        agent.run()
    except KeyboardInterrupt:
        console.print("\n[bold red]Exiting...[/bold red]")
    def __init__(self, provider: str, api_key: str = None, base_url: str = None, model: str = None):
        self.provider = provider
        self.model = model
        
        if provider == "openai":
            self.client = OpenAI(api_key=api_key)
            self.model = model or "gpt-4o"
        elif provider == "ollama":
            # Ollama is compatible with OpenAI client if we point to local base_url
            self.client = OpenAI(
                base_url=base_url or "http://localhost:11434/v1",
                api_key="ollama", # required but ignored
            )
            self.model = model or "llama3" # default to llama3 if not specified
            
    def create_completion(self, system_prompt: str, user_prompt: str) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            console.print(f"[bold red]LLM Error ({self.provider}): {e}[/bold red]")
            if self.provider == "ollama":
                console.print("[yellow]Tip: Ensure Ollama is running (e.g., 'ollama serve') and the model is pulled (e.g., 'ollama pull llama3')[/yellow]")
            return ""

class Executor:
    def __init__(self, image_path: str):
        self.image_path = image_path
        self.vol_script = os.path.join(os.path.dirname(__file__), "volatility3", "vol.py")

    def get_available_plugins(self) -> List[str]:
        """
        Runs vol.py --help to get a list of available plugins.
        """
        if not os.path.exists(self.vol_script):
            return []
            
        cmd = [sys.executable, self.vol_script, "-f", self.image_path, "--help"]
        try:
            # This might take a moment as it scans for plugins
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            output = result.stdout + result.stderr
            
            # Parse plugins from the output. 
            # Volatility 3 help lists plugins usually in a section. 
            # A simple regex to find words starting with 'windows.', 'linux.', 'mac.' might work.
            plugins = re.findall(r'(windows\.[a-zA-Z0-9_]+|linux\.[a-zA-Z0-9_]+|mac\.[a-zA-Z0-9_]+)', output)
            return sorted(list(set(plugins)))
        except Exception:
            return []

    def execute_plugin(self, plugin_name: str) -> str:
        """
        Executes a Volatility 3 plugin and returns the output.
        """
        console.print(f"[bold yellow]Running plugin: {plugin_name}...[/bold yellow]")
        
        if not os.path.exists(self.vol_script):
             console.print(f"[bold red]Error: vol.py not found at {self.vol_script}[/bold red]")
             return "Error: Volatility 3 script not found."

        cmd = [sys.executable, self.vol_script, "-f", self.image_path, plugin_name]
        
        try:
            # Capture stdout and stderr
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if result.returncode != 0:
                console.print(f"[bold red]Plugin {plugin_name} failed![/bold red]")
                # console.print(f"Error: {result.stderr}") # Reduce noise
                return f"Error running {plugin_name}: {result.stderr}"
            
            return result.stdout
        except Exception as e:
            return f"Execution exception: {str(e)}"

class Planner:
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client

    def create_plan(self, scenario: str, available_plugins: List[str]) -> List[Dict[str, str]]:
        """
        Generates a list of Volatility 3 plugins to run based on the user scenario.
        """
        console.print(f"[bold blue]Thinking ({self.llm.provider})... Generating investigation plan...[/bold blue]")
        
        # Filter plugins to keep prompt size manageable, or just provide the full list if not too huge.
        # For now, let's provide the full list but formatted nicely.
        plugin_list_str = ", ".join(available_plugins)
        
        prompt = f"""
        You are an expert digital forensics investigator using Volatility 3.
        
        User Scenario: "{scenario}"
        
        AVAILABLE PLUGINS:
        [{plugin_list_str}]
        
        Based on this scenario, select the most relevant Volatility 3 plugins from the AVAILABLE PLUGINS list above.
        DO NOT invent new plugins. Use ONLY the ones listed.
        
        Return ONLY a JSON array of objects, where each object has:
        - "plugin": The exact plugin name from the list.
        - "reason": A brief explanation of why this plugin is relevant.
        
        Order the plugins logically.
        """
        
        content = self.llm.create_completion("You are a helpful forensic assistant.", prompt)
        
        if not content:
            return []

        try:
            # Use regex to find the JSON array
            match = re.search(r'\[.*\]', content, re.DOTALL)
            if match:
                json_str = match.group(0)
                plan = json.loads(json_str)
            else:
                # Fallback to original cleaning if regex fails (unlikely but safe)
                if content.startswith("```json"):
                    content = content[7:]
                if content.startswith("```"):
                    content = content[3:]
                if content.endswith("```"):
                    content = content[:-3]
                plan = json.loads(content.strip())
            
            # Validate plan against available plugins
            valid_plan = []
            for step in plan:
                if step['plugin'] in available_plugins:
                    valid_plan.append(step)
                else:
                    console.print(f"[yellow]Warning: LLM suggested invalid plugin '{step['plugin']}'. Skipping.[/yellow]")
            
            return valid_plan
        except json.JSONDecodeError:
            console.print(f"[bold red]Error parsing plan JSON from LLM. Raw output:[/bold red]\n{content}")
            return []
        except Exception as e:
            console.print(f"[bold red]Error generating plan: {e}[/bold red]")
            return []

class Analyst:
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client

    def analyze_output(self, plugin_name: str, output: str, scenario: str) -> str:
        """
        Analyzes the raw output of a plugin in the context of the scenario.
        """
        console.print(f"[bold blue]Analyzing output for {plugin_name} ({self.llm.provider})...[/bold blue]")
        
        # Truncate output if it's too long for the context window
        max_len = 50000 
        if len(output) > max_len:
            output = output[:max_len] + "\n...[Output Truncated]..."

        prompt = f"""
        You are a forensic analyst.
        
        Scenario: "{scenario}"
        Plugin Run: "{plugin_name}"
        
        Output:
        {output}
        
        Analyze this output. 
        1. Identify any suspicious entries related to the scenario.
        2. Explain what they mean.
        3. If nothing suspicious is found, state that clearly.
        
        Keep your analysis concise and factual.
        """
        
        return self.llm.create_completion("You are a sharp-eyed forensic analyst.", prompt)

class Reporter:
    def generate_report(self, scenario: str, findings: List[Dict[str, Any]]) -> str:
        """
        Generates an interactive HTML report with Mermaid diagrams.
        """
        console.print("[bold green]Generating final report...[/bold green]")
        
        # Generate Mermaid Graph for the flow
        graph_nodes = ["Start[Start Investigation]"]
        for i, item in enumerate(findings):
            plugin = item['plugin']
            node_id = f"Step{i}"
            graph_nodes.append(f"{node_id}[Run {plugin}]")
        
        graph_edges = []
        for i in range(len(graph_nodes) - 1):
            graph_edges.append(f"{graph_nodes[i].split('[')[0]} --> {graph_nodes[i+1].split('[')[0]}")
        graph_edges.append(f"{graph_nodes[-1].split('[')[0]} --> End[Report Generated]")
        
        mermaid_graph = "graph TD;\n" + ";\n".join(graph_edges) + ";"

        report_html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Forensic Investigation Report</title>
            <style>
                :root {{
                    --primary-color: #2c3e50;
                    --secondary-color: #3498db;
                    --accent-color: #e67e22;
                    --bg-color: #f4f6f7;
                    --text-color: #333;
                }}
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; background-color: var(--bg-color); color: var(--text-color); }}
                .container {{ max-width: 1000px; margin: 40px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                h1 {{ color: var(--primary-color); border-bottom: 2px solid var(--secondary-color); padding-bottom: 10px; }}
                h2 {{ color: var(--primary-color); margin-top: 30px; }}
                .scenario-box {{ background: #e8f6f3; padding: 20px; border-left: 5px solid #1abc9c; margin-bottom: 30px; }}
                .finding {{ border: 1px solid #ddd; margin-bottom: 20px; border-radius: 5px; overflow: hidden; }}
                .finding-header {{ background: #ecf0f1; padding: 15px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }}
                .finding-header:hover {{ background: #e0e6e8; }}
                .finding-header h3 {{ margin: 0; color: var(--primary-color); font-size: 1.1em; }}
                .finding-content {{ padding: 20px; display: none; }}
                .finding-content.active {{ display: block; }}
                .badge {{ background: var(--accent-color); color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }}
                .analysis-box {{ background: #fdf2e9; padding: 15px; border-left: 4px solid var(--accent-color); margin-bottom: 15px; }}
                pre {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Consolas', monospace; font-size: 0.9em; }}
                .toggle-icon {{ font-weight: bold; transition: transform 0.3s; }}
                .active .toggle-icon {{ transform: rotate(180deg); }}
            </style>
            <script type="module">
                import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
                mermaid.initialize({{ startOnLoad: true }});
            </script>
        </head>
        <body>
            <div class="container">
                <h1>Forensic Investigation Report</h1>
                
                <div class="scenario-box">
                    <strong>Scenario:</strong> {scenario}
                </div>
                
                <h2>Investigation Flow</h2>
                <div class="mermaid">
                {mermaid_graph}
                </div>
                
                <h2>Detailed Findings</h2>
                <p>Click on each step to view details.</p>
        """
        
        for i, item in enumerate(findings):
            plugin = item['plugin']
            analysis = item['analysis']
            raw_output = item['raw_output']
            # Escape HTML in raw output
            raw_output_safe = raw_output.replace("<", "&lt;").replace(">", "&gt;")
            analysis_safe = analysis.replace("\n", "<br>")
            
            report_html += f"""
            <div class="finding">
                <div class="finding-header" onclick="this.nextElementSibling.classList.toggle('active'); this.querySelector('.toggle-icon').innerText = this.nextElementSibling.classList.contains('active') ? '▼' : '▶';">
                    <h3>Step {i+1}: {plugin}</h3>
                    <span class="toggle-icon">▶</span>
                </div>
                <div class="finding-content">
                    <div class="analysis-box">
                        <strong>AI Analysis:</strong><br>
                        {analysis_safe}
                    </div>
                    <details>
                        <summary>View Raw Output</summary>
                        <pre>{raw_output_safe}</pre>
                    </details>
                </div>
            </div>
            """
            
        report_html += """
            </div>
        </body>
        </html>
        """
        return report_html

class Investigator:
    def __init__(self):
        self.show_welcome()
        self.setup_llm()
        self.planner = Planner(self.llm_client)
        self.analyst = Analyst(self.llm_client)
        self.reporter = Reporter()
        self.findings = []

    def show_welcome(self):
        batman_art = r"""
       _==/          i     i          \==_
     /XX/            |\___/|            \XX\
   /XXXX\            |XXXXX|            /XXXX\
  |XXXXXX\_         _XXXXXXX_         _/XXXXXX|
 XXXXXXXXXXXxxxxxxxXXXXXXXXXXXxxxxxxxXXXXXXXXXXX
|XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX|
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
|XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX|
 XXXXXX/^^^^"\XXXXXXXXXXXXXXXXXXXXX/^^^^^\XXXXXX
  |XXX|       \XXX/^^\XXXXX/^^\XXX/       |XXX|
    \XX\       \X/    \XXX/    \X/       /XX/
       "\       "      \X/      "      /"
        """
        
        console.print("[bold black on yellow]  THE DARK KNIGHT INVESTIGATOR  [/bold black on yellow]", justify="center")
        
        # Simple animation effect
        import time
        for line in batman_art.split("\n"):
            console.print(f"[bold grey30]{line}[/bold grey30]", justify="center")
            time.sleep(0.05)
            
        console.print("\n[bold cyan]\"It's not who I am underneath, but what I do that defines me.\"[/bold cyan]", justify="center")
        console.print("[italic]...initializing forensic protocols...[/italic]\n", justify="center")
        time.sleep(1)

    def setup_llm(self):
        console.print(Panel.fit(
            "[bold cyan]Agentic Forensic Investigator[/bold cyan]\n"
            "[italic]Created by Ishan Perera[/italic]\n\n"
            "Choose your AI Brain:\n"
            "1. [bold green]Cloud (OpenAI)[/bold green]: Smartest, Faster, Requires API Key & Internet.\n"
            "2. [bold yellow]Local (Ollama)[/bold yellow]: Private, Offline, Requires Local Model (e.g., Llama 3).",
            title="Welcome"
        ))
        
        choice = Prompt.ask("Select Option", choices=["1", "2"], default="1")
        
        if choice == "1":
            api_key = os.environ.get("OPENAI_API_KEY")
            if not api_key:
                console.print("\n[yellow]To use OpenAI, you need an API Key.[/yellow]")
                console.print("[yellow]Get one here: https://platform.openai.com/api-keys[/yellow]")
                api_key = Prompt.ask("Enter your OpenAI API Key (input will be hidden)", password=True)
            self.llm_client = LLMClient("openai", api_key=api_key)
            console.print("[green]Using OpenAI (Cloud)[/green]")
            
        else:
            base_url = Prompt.ask("Enter Ollama URL", default="http://localhost:11434/v1")
            # Ensure URL ends with /v1 for OpenAI compatibility
            if not base_url.endswith("/v1") and not base_url.endswith("/v1/"):
                base_url = base_url.rstrip("/") + "/v1"
            
            model = Prompt.ask("Enter Model Name", default="llama3")
            self.llm_client = LLMClient("ollama", base_url=base_url, model=model)
            console.print(f"[yellow]Using Ollama (Local) - Model: {model}[/yellow]")

    def run(self):
        # 1. Get Image Path
        image_path = console.input("Enter the path to the memory image file: ").strip()
        if not os.path.exists(image_path):
            console.print("[bold red]File not found![/bold red]")
            return

        self.executor = Executor(image_path)
        
        # 1.5 Pre-fetch plugins
        console.print("[bold blue]Scanning for available plugins...[/bold blue]")
        available_plugins = self.executor.get_available_plugins()
        if not available_plugins:
            console.print("[bold red]Could not list plugins. Is Volatility 3 working?[/bold red]")
            # Continue anyway, maybe list was empty but execution might work? Unlikely.
            # But let's not crash.
        else:
            console.print(f"[green]Found {len(available_plugins)} plugins.[/green]")

        # 2. Get Scenario
        scenario = console.input("Describe the scenario/incident (e.g., 'Suspicious network activity detected'): ").strip()
        
        # 3. Plan
        plan = self.planner.create_plan(scenario, available_plugins)
        if not plan:
            console.print("[red]No valid plan could be generated.[/red]")
            return

        # Display Plan
        table = Table(title="Proposed Investigation Plan")
        table.add_column("Step", style="cyan")
        table.add_column("Plugin", style="magenta")
        table.add_column("Reason", style="green")
        
        for i, step in enumerate(plan):
            table.add_row(str(i+1), step['plugin'], step['reason'])
            
        console.print(table)
        
        if not Confirm.ask("Do you want to proceed with this plan?"):
            console.print("Investigation aborted.")
            return

        # 4. Execute & Analyze
        for step in plan:
            plugin = step['plugin']
            
            # Execute
            raw_output = self.executor.execute_plugin(plugin)
            
            # Analyze
            analysis = self.analyst.analyze_output(plugin, raw_output, scenario)
            
            # Store
            self.findings.append({
                "plugin": plugin,
                "raw_output": raw_output,
                "analysis": analysis
            })
            
            console.print(f"[green]Analysis for {plugin} complete.[/green]")
            console.print("-" * 40)

        # 5. Report
        report_content = self.reporter.generate_report(scenario, self.findings)
        report_file = "investigation_report.html"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report_content)
            
        console.print(f"[bold green]Report generated: {os.path.abspath(report_file)}[/bold green]")

if __name__ == "__main__":
    try:
        agent = Investigator()
        agent.run()
    except KeyboardInterrupt:
        console.print("\n[bold red]Exiting...[/bold red]")
