import { describe, expect, it } from "vitest";
import { TestDriver } from "testdriverai/vitest/hooks";

// Sample TestDriver tests for the Apotrope production website (https://apotrope.sh).
//
// Apotrope is a portable, offline Windows security auditor. Its production "app"
// is the marketing/docs site served via GitHub Pages from the repo's /docs folder.
// The tool intentionally requires no account or signup, so there are no
// credentials to use — these tests cover public, credential-free user journeys
// through the live production site.
describe("apotrope.sh production site", () => {
  it("loads the landing page with the hero and download CTA", async (context) => {
    const testdriver = TestDriver(context);

    await testdriver.provision.chrome({ url: "https://apotrope.sh" });
    await testdriver.wait(3000);

    const heroVisible = await testdriver.assert(
      "the page shows the hero headline about security posture auditing for Windows and a green \"Download apotrope.exe\" button",
    );
    expect(heroVisible).toBeTruthy();
  });

  it("navigates to the Scoring section from the top nav", async (context) => {
    const testdriver = TestDriver(context);

    await testdriver.provision.chrome({ url: "https://apotrope.sh" });
    await testdriver.wait(3000);

    // Click the "Scoring" item in the top navigation bar.
    await testdriver.find("the \"Scoring\" link in the top navigation bar").click();
    await testdriver.wait(2000);

    // The scoring section explains the 0-100 score and A-F letter grades.
    const scoringVisible = await testdriver.assert(
      "the Scoring section is shown, describing a 0-100 score with A through F letter grades",
    );
    expect(scoringVisible).toBeTruthy();
  });

  it("opens the 'Lynis for Windows' comparison page", async (context) => {
    const testdriver = TestDriver(context);

    // Deep-link directly to the comparison article on the production site.
    await testdriver.provision.chrome({ url: "https://apotrope.sh/lynis-for-windows/" });
    await testdriver.wait(3000);

    const comparisonVisible = await testdriver.assert(
      "the page is an article about whether there is a Lynis for Windows and mentions Apotrope",
    );
    expect(comparisonVisible).toBeTruthy();
  });
});
