# tests/test_github_mcp.py

"""GitHubMCPService with PyGithub mocked. No network."""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from github import GithubException

from app.core.exceptions import GitHubMCPError
from app.services.github_mcp import GitHubMCPService

NOW = datetime(2026, 1, 1, tzinfo=UTC)


@pytest.fixture
def service():
    svc = GitHubMCPService()
    svc._client = MagicMock()
    return svc


def fake_pr():
    pr = MagicMock()
    pr.id, pr.number, pr.title, pr.body, pr.state = 1, 42, "Fix thing", None, "open"
    pr.user = SimpleNamespace(
        login="octo", id=5, avatar_url="a", html_url="h", type="User", site_admin=False
    )
    pr.created_at = pr.updated_at = NOW
    pr.merged_at = pr.closed_at = None
    pr.html_url = "https://github.com/octo/repo/pull/42"
    pr.diff_url = pr.patch_url = "u"
    pr.head = SimpleNamespace(ref="feat", sha="aaa", label="octo:feat", repo=None)
    pr.base = SimpleNamespace(
        ref="main", sha="bbb", label="octo:main", repo=SimpleNamespace(full_name="octo/repo")
    )
    pr.additions, pr.deletions, pr.changed_files, pr.commits = 10, 2, 1, 1
    pr.mergeable, pr.mergeable_state, pr.merged, pr.draft = True, "clean", False, False
    pr.get_files.return_value = [
        SimpleNamespace(
            filename="a.py",
            status="modified",
            additions=10,
            deletions=2,
            changes=12,
            patch="@@ -1 +1 @@\n+x",
        ),
        SimpleNamespace(
            filename="img.png", status="added", additions=0, deletions=0, changes=0, patch=None
        ),
    ]
    return pr


class TestParsePrUrl:
    @pytest.mark.parametrize(
        "url, expected",
        [
            ("https://github.com/octo/repo/pull/123", ("octo", "repo", 123)),
            ("https://github.com/a-b/c.d_e/pull/1", ("a-b", "c.d_e", 1)),
            ("https://github.com/octo/repo/pull/9/files", ("octo", "repo", 9)),
        ],
    )
    def test_valid(self, service, url, expected):
        assert service.parse_pr_url(url) == expected

    @pytest.mark.parametrize(
        "url",
        [
            "",
            "not a url",
            "https://github.com/octo/repo",
            "https://github.com/octo/repo/issues/5",
            "https://github.com/octo/repo/pull/abc",
            "http://github.com/octo/repo/pull/1",
            "https://gitlab.com/octo/repo/pull/1",
        ],
    )
    def test_invalid(self, service, url):
        with pytest.raises(GitHubMCPError):
            service.parse_pr_url(url)


class TestFetching:
    @pytest.mark.asyncio
    async def test_get_pull_request(self, service):
        service._client.get_repo.return_value.get_pull.return_value = fake_pr()
        pr = await service.get_pull_request("octo", "repo", 42)
        service._client.get_repo.assert_called_once_with("octo/repo")
        assert pr.number == 42
        assert pr.body == ""  # None body becomes empty string
        assert pr.user.login == "octo"
        assert pr.head["repo"] is None
        assert pr.base["repo"] == "octo/repo"
        assert (pr.additions, pr.deletions) == (10, 2)

    @pytest.mark.asyncio
    async def test_get_pr_diff_skips_files_without_patch(self, service):
        service._client.get_repo.return_value.get_pull.return_value = fake_pr()
        diff = await service.get_pr_diff("octo", "repo", 42)
        assert "diff --git a/a.py b/a.py" in diff
        assert "+x" in diff
        assert "img.png" not in diff

    @pytest.mark.asyncio
    async def test_list_pr_files(self, service):
        service._client.get_repo.return_value.get_pull.return_value = fake_pr()
        files = await service.list_pr_files("octo", "repo", 42)
        assert [f.filename for f in files] == ["a.py", "img.png"]
        assert files[1].patch == ""

    @pytest.mark.asyncio
    async def test_get_pr_with_diff(self, service):
        service._client.get_repo.return_value.get_pull.return_value = fake_pr()
        pr, diff = await service.get_pr_with_diff("octo", "repo", 42)
        assert diff.pr_number == 42
        assert diff.total_changes == pr.additions + pr.deletions == 12
        assert len(diff.files) == 2
        assert "a.py" in diff.raw_diff

    @pytest.mark.asyncio
    async def test_get_file_content_decodes(self, service):
        repo = service._client.get_repo.return_value
        repo.get_contents.return_value = SimpleNamespace(decoded_content=b"print('hi')")
        assert await service.get_file_content("octo", "repo", "a.py", ref="main") == "print('hi')"
        repo.get_contents.assert_called_once_with("a.py", ref="main")

    @pytest.mark.asyncio
    async def test_get_pr_reviews_returns_empty_on_failure(self, service):
        service._client.get_repo.side_effect = GithubException(500, {}, None)
        assert await service.get_pr_reviews("octo", "repo", 42) == []


class TestErrors:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "method", ["get_pull_request", "get_pr_diff", "list_pr_files", "get_pr_with_diff"]
    )
    async def test_github_error_becomes_github_mcp_error(self, service, method):
        service._client.get_repo.side_effect = GithubException(404, {"message": "Not Found"}, None)
        with pytest.raises(GitHubMCPError):
            await getattr(service, method)("octo", "repo", 42)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "method", ["get_pull_request", "get_pr_diff", "list_pr_files", "get_pr_reviews"]
    )
    async def test_uninitialised_client_raises(self, method):
        svc = GitHubMCPService()  # no context manager entered
        with pytest.raises(GitHubMCPError):
            await getattr(svc, method)("octo", "repo", 1)

    @pytest.mark.asyncio
    async def test_context_manager_without_connection_test(self, monkeypatch):
        monkeypatch.setenv("SKIP_GITHUB_CONNECTION_TEST", "true")
        fake_client = MagicMock()
        monkeypatch.setattr("app.services.github_mcp.Github", MagicMock(return_value=fake_client))
        async with GitHubMCPService() as svc:
            assert svc._client is fake_client
            fake_client.get_user.assert_not_called()
        fake_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_context_manager_connection_failure(self, monkeypatch):
        monkeypatch.delenv("SKIP_GITHUB_CONNECTION_TEST", raising=False)
        fake_client = MagicMock()
        fake_client.get_user.side_effect = GithubException(
            401, {"message": "Bad credentials"}, None
        )
        monkeypatch.setattr("app.services.github_mcp.Github", MagicMock(return_value=fake_client))
        with pytest.raises(GitHubMCPError):
            async with GitHubMCPService():
                pass


class TestPostPrComment:
    @pytest.mark.asyncio
    async def test_posts_comment_on_the_pr(self, service):
        await service.post_pr_comment("octo", "repo", 42, "hello")
        repo = service._client.get_repo
        repo.assert_called_once_with("octo/repo")
        repo.return_value.get_issue.assert_called_once_with(42)
        create = repo.return_value.get_issue.return_value.create_comment
        create.assert_called_once_with("hello")

    @pytest.mark.asyncio
    async def test_github_error_becomes_github_mcp_error(self, service):
        issue = service._client.get_repo.return_value.get_issue.return_value
        issue.create_comment.side_effect = GithubException(403, {"message": "no"}, None)
        with pytest.raises(GitHubMCPError, match="403"):
            await service.post_pr_comment("octo", "repo", 42, "hello")

    @pytest.mark.asyncio
    async def test_uninitialised_client_raises(self):
        with pytest.raises(GitHubMCPError):
            await GitHubMCPService().post_pr_comment("octo", "repo", 42, "hello")
