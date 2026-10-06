import ast
from hatchling.metadata.plugin.interface import MetadataHookInterface

class CustomMetadataHook(MetadataHookInterface):
    def update(self, metadata: dict) -> None:
        """Dynamically injects values extracted from version.py into project metadata."""
        filepathVersion = "src/vinetto/version.py"

        # Read and parse the version file...
        with open(filepathVersion, "r", encoding="utf-8") as fileVersion:
            tree = ast.parse( fileVersion.read() )

        variables = {}
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        try:
                            variables[target.id] = ast.literal_eval(node.value)
                        except ValueError:
                            pass # Skip non-literal assignments

        # Extract authors...
        authors = variables.get("authors", [])
        if authors:
            metadata["authors"] = authors

        # Extract maintainers...
        maints = variables.get("maintainers", [])
        if maints:
            metadata["authors"] = maints

        # Extract URLs...
        homepage = variables.get("homepage", "unknown")
        repository = variables.get("repository", "unknown")
        bug_tracker = variables.get("bug_tracker", "unknown")
        documentation = variables.get("documentation", "unknown")
        changelog = variables.get("changelog", "unknown")
        metadata["urls"] = {
            "Homepage": homepage,
            "Repository": repository,
            "Bug Tracker": bug_tracker,
            "Documentation": documentation,
            "Changelog": changelog,
        }