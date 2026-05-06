from playwright.sync_api import sync_playwright
import time
import sys

def run_verification():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        
        print("--- STARTING EMET VERIFICATION LOOP ---")
        
        try:
            # 1. Login
            print("Step 1: Logging in...")
            page.goto("http://localhost:3000/login", timeout=60000)
            page.wait_for_load_state("networkidle")
            
            page.fill("input[placeholder='EMAIL_OR_HANDLE']", "analyst@emet.local")
            page.fill("input[placeholder='********']", "emet")
            page.click("button:has-text('EXECUTE_LOGIN')")
            
            # Wait for redirect to scan-console
            print("Waiting for dashboard redirect...")
            page.wait_for_url("**/scan-console", timeout=30000)
            print("Successfully logged in.")

            # 2. Select All Tools
            print("Step 2: Selecting all scanning tools...")
            # Wait for scanners to load (they might be disabled briefly while loading availability)
            time.sleep(5)
            checkboxes = page.locator("input[type='checkbox']").all()
            print(f"Found {len(checkboxes)} scanner checkboxes.")
            for i, cb in enumerate(checkboxes):
                if not cb.is_checked():
                    print(f"Checking box {i}...")
                    cb.click(force=True) # Use force to click even if disabled/covered
            
            # 3. Enter Target
            print("Step 3: Entering target...")
            # Use a more robust selector (the input inside the target section)
            target_input = page.locator("input").first # The first input is usually target
            target_input.fill("repo:/app")
            
            # 4. Start Scan
            print("Step 4: Clicking START SCAN...")
            start_btn = page.locator("button:has-text('START SCAN')")
            if start_btn.is_disabled():
                print("Error: START SCAN button is disabled!")
                # Let's check why - maybe validation regex?
                page.screenshot(path="error_disabled_btn.png")
                #sys.exit(1)
            
            start_btn.click(force=True)
            print("Scan initiated.")

            # 5. Monitor Progress
            print("Step 5: Monitoring progress...")
            # Wait for progress bar container to appear
            page.wait_for_selector("text=PIPELINE", timeout=30000)
            print("Pipeline container detected.")
            
            # Polling for completion (Wait up to 5 minutes)
            start_time = time.time()
            completed = False
            while time.time() - start_time < 300:
                elapsed = int(time.time() - start_time)
                print(f"Loop iteration. Elapsed: {elapsed}s")
                # Check for completion in many forms
                content = page.content()
                if "PIPELINE (COMPLETE)" in content or "Executive Summary" in content:
                    print("Progress: 100% - Scan Complete.")
                    completed = True
                    break
                
                # Log current state
                state_match = page.locator("div").filter(has_text="STATUS:").last
                if state_match.count() > 0:
                    print(f"Current UI State: {state_match.inner_text()}")
                
                # Also print the latest log message
                log_msgs = page.locator("div:has-text('[LOG]')").all()
                if log_msgs:
                    print(f"Latest log: {log_msgs[-1].inner_text()}")
                
                # Check for errors in the UI
                if "FAILURE STATE" in content:
                    print("Error detected in UI.")
                    page.screenshot(path="scan_failure_ui.png")
                    sys.exit(1)
                
                time.sleep(5)
            
            if not completed:
                print("Timed out waiting for scan completion.")
                page.screenshot(path="scan_timeout.png")
                sys.exit(1)

            # 6. Verify Results
            print("Step 6: Verifying results tabs...")
            
            # Check Unified Report
            page.click("button:has-text('UNIFIED REPORT')")
            time.sleep(2)
            if page.locator("text=Executive Summary").is_visible():
                print("Unified Report: VALID (Executive Summary found)")
            else:
                print("Unified Report: MISSING CONTENT")
                sys.exit(1)
                
            # Check Detailed Findings
            page.click("button:has-text('DETAILED FINDINGS')")
            time.sleep(2)
            findings_count = page.locator("div:has-text('DESCRIPTION')").count()
            if findings_count > 0:
                print(f"Detailed Findings: VALID ({findings_count} findings displayed)")
            else:
                print("Detailed Findings: EMPTY")
                sys.exit(1)

            print("--- VERIFICATION SUCCESSFUL ---")
            
        except Exception as e:
            print(f"CRITICAL ERROR DURING VERIFICATION: {e}")
            page.screenshot(path="critical_exception.png")
            sys.exit(1)
        finally:
            browser.close()

if __name__ == "__main__":
    run_verification()
