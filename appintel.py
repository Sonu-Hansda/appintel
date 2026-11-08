#!/usr/bin/env python3

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))

from modules.dns_recon import run_dns_recon
from utils import validate_domain
from models import ScanResult


app = typer.Typer(
    name="appintel",
    help="Web application reconnaissance",
    add_completion=False
)
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Domain to scan (e.g., example.com)"),
    output: str = typer.Option("output", "--output", "-o", help="Output directory for results"),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "-w", help="Custom subdomain wordlist file")
):
    if not validate_domain(target):
        console.print(f"[red]Error: '{target}' is not a valid domain[/red]")
        raise typer.Exit(1)
    
    custom_words = None
    if wordlist:
        try:
            with open(wordlist) as f:
                custom_words = [line.strip() for line in f if line.strip()]
            console.print(f"[blue]Loaded {len(custom_words)} words from {wordlist}[/blue]")
        except FileNotFoundError:
            console.print(f"[red]Wordlist not found: {wordlist}[/red]")
            raise typer.Exit(1)
    
    try:
        result = run_dns_recon(target, output_dir=output, wordlist=custom_words)
        display_results(result)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(130)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


def display_results(result: ScanResult):

    console.print(f"\n[bold green]Results for {result.target}[/bold green]")
    
    if result.subdomains:
        table = Table(title="Discovered Subdomains")
        table.add_column("Subdomain", style="cyan")
        table.add_column("IP Address", style="magenta")
        table.add_column("Source", style="green")
        
        for sub in result.subdomains:
            table.add_row(sub.name, sub.ip or "N/A", sub.source)
        
        console.print(table)
    
    dns = result.dns_records
    if any([dns.A, dns.AAAA, dns.MX, dns.TXT, dns.NS]):
        records_text = []
        if dns.A:
            records_text.append(f"[bold]A:[/bold] {', '.join(dns.A)}")
        if dns.AAAA:
            records_text.append(f"[bold]AAAA:[/bold] {', '.join(dns.AAAA)}")
        if dns.MX:
            records_text.append(f"[bold]MX:[/bold] {', '.join(dns.MX)}")
        if dns.TXT:
            records_text.append(f"[bold]TXT:[/bold] {dns.TXT[0][:50]}{'...' if len(dns.TXT[0]) > 50 else ''}")
        if dns.NS:
            records_text.append(f"[bold]NS:[/bold] {', '.join(dns.NS)}")
        
        console.print(Panel(
            "\n".join(records_text),
            title="DNS Records",
            border_style="blue"
        ))
    
    if result.live_hosts:
        table = Table(title="Live HTTP/HTTPS Hosts")
        table.add_column("URL", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Title", style="magenta")
        table.add_column("IP", style="yellow")
        
        for host in result.live_hosts:
            status_color = "green" if host.status_code == 200 else "yellow" if host.status_code < 400 else "red"
            table.add_row(
                host.url,
                f"[{status_color}]{host.status_code}[/{status_color}]",
                (host.title or "N/A")[:30],
                host.ip or "N/A"
            )
        
        console.print(table)


@app.command()
def version():
    console.print("[bold cyan]AppIntel[/bold cyan] v0.1.0")
    console.print("Phase 1: DNS & Infrastructure Reconnaissance")
    console.print("\n[dim]No external Go tools required. Uses dnspython, requests, socket.[/dim]")


if __name__ == "__main__":
    app()