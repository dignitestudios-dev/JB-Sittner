import React, { useState, useEffect } from "react";
import { IoMdClose } from "react-icons/io";
import { db } from "../firbase/FirebaseInit";
import { doc, setDoc, getDoc } from "firebase/firestore";
import { toast } from "react-toastify";

export default function SettingModal({ isOpen, setIsOpen }) {
  const [days, setDays] = useState(7);
  const [hours, setHours] = useState(0);
  const [loading, setLoading] = useState(false);
  const [fetching, setFetching] = useState(true);

  // ✅ Fetch from Firestore when modal opens
  useEffect(() => {
    const fetchSetting = async () => {
      try {
        setFetching(true);
        const ref = doc(db, "settings", "reminder");
        const snap = await getDoc(ref);
        if (snap.exists()) {
          const data = snap.data();
          setDays(data.days);
          setHours(data.hours);
        }
      } catch (err) {
        console.error("Error fetching reminder setting:", err);
        toast.error("Failed to fetch reminder setting.");
      } finally {
        setFetching(false);
      }
    };
    if (isOpen) fetchSetting();
  }, [isOpen]);

  // ✅ Save settings to Firestore
  const handleSave = async () => {
    if ((!days && !hours) || (days <= 0 && hours <= 0)) {
      toast.error("Please enter a valid number of days or hours.");
      return;
    }

    if (days > 30 || hours > 23) {
      toast.error("Days must be 30 or less, and hours must be 23 or less.");
      return;
    }

    try {
      setLoading(true);

      await setDoc(doc(db, "settings", "reminder"), {
        days: Number(days) || 0,
        hours: Number(hours) || 0,
        updatedAt: new Date(),
      });

      toast.success("Reminder setting saved successfully!");
      setIsOpen(false);
    } catch (err) {
      console.error("Error saving setting:", err);
      toast.error("Failed to save setting.");
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="h-screen">
      <div className="justify-center items-center flex overflow-x-hidden overflow-y-auto fixed inset-0 z-50 outline-none focus:outline-none">
        <div className="w-[450px] h-auto">
          <div className="border-0 rounded-[16px] p-5 shadow-lg flex flex-col w-full bg-white outline-none focus:outline-none">
            {/* Header */}
            <div className="flex justify-between items-center mb-4">
              <h3 className="font-[600] text-[18px]">
                Set Reminder Text Setting
              </h3>
              <button onClick={() => setIsOpen(false)}>
                <IoMdClose size={22} />
              </button>
            </div>

            {/* Body */}
            <div className="flex flex-col gap-4">
              <label className="font-medium text-[15px] text-gray-700">
                Send reminder after:
              </label>

              {fetching ? (
                <p className="text-gray-500 text-sm">
                  Loading current setting...
                </p>
              ) : (
                <div className="flex gap-3">
                  <div className="flex flex-col">
                    <span className="text-sm text-gray-600 mb-1">Days</span>
                    <input
                      type="number"
                      min="0"
                      max="30"
                      value={days}
                      onChange={(e) => {
                        const value = e.target.value;

                        // empty allow (backspace ke liye)
                        if (value === "") {
                          setDays("");
                          return;
                        }

                        const number = Number(value);

                        // sirf 0 se 30 tak allow
                        if (number >= 0 && number <= 30) {
                          setDays(number);
                        }
                      }}
                      onKeyDown={(e) => {
                        // minus key block
                        if (e.key === "-" || e.key === "e") {
                          e.preventDefault();
                        }
                      }}
                      className="border rounded-lg px-3 py-2 w-[120px] focus:ring-2 focus:ring-green-500 focus:outline-none"
                      placeholder="Days"
                    />
                  </div>

                  <div className="flex flex-col">
                    <span className="text-sm text-gray-600 mb-1">Hours</span>
                    <input
                      type="number"
                      min="0"
                      max="23"
                      value={hours}
                      onChange={(e) => {
                        const value = e.target.value;

                        // empty allow (delete/backspace)
                        if (value === "") {
                          setHours("");
                          return;
                        }

                        const num = Number(value);

                        // sirf 0–23 allow
                        if (num >= 0 && num <= 23) {
                          setHours(num);
                        }
                      }}
                      onKeyDown={(e) => {
                        // minus & e block
                        if (e.key === "-" || e.key === "e") {
                          e.preventDefault();
                        }
                      }}
                      className="border rounded-lg px-3 py-2 w-[120px] focus:ring-2 focus:ring-green-500 focus:outline-none"
                      placeholder="Hours"
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="flex justify-end mt-5">
              <button
                onClick={handleSave}
                disabled={loading || fetching}
                className="bg-green-600 text-white px-5 py-2 rounded-lg hover:bg-green-700 transition disabled:opacity-50"
              >
                {loading ? "Saving..." : "Save Setting"}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* background overlay */}
      <div className="opacity-25 fixed h-screen inset-0 z-40 bg-black"></div>
    </div>
  );
}
