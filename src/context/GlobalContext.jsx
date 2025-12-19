import React, { createContext, useEffect, useState } from "react";
import {
  collection,
  db,
  onSnapshot,
  query,
  getDocs,
  addDoc,
  updateDoc,
  orderBy,
} from "../firbase/FirebaseInit";
import Cookies from "js-cookie";
import moment from "moment";
import "moment-timezone";
export const MyContext = createContext();

export const MyContextProvider = ({ children }) => {
  const currentTime = new Date();
  const formattedTime = `${currentTime.getHours() % 12 || 12}:${String(
    currentTime.getMinutes()
  ).padStart(2, "0")} ${currentTime.getHours() >= 12 ? "PM" : "AM"}`;

  const [PasswordSuccessFullChange, setPasswordSuccessFullChange] =
    useState(false);
  const [ChangePassword, setIsChangePassword] = useState(false);
  const [LogOut, setIsLogOut] = useState(false);
  const [IsDropdownOpen, setIsDropdown] = useState(false);
  const [isEditGroup, setEditGroup] = useState(false);
  const [LookScreen, setLookScreen] = useState(false);
  const [DeleteSchedule, setIsDeleteSchedule] = useState(false);
  const [DeleteProfile, setIsDeleteProfile] = useState(false);
  const [viewAll, setIsViewAll] = useState(false);
  const [AddMem, setIsAddMem] = useState(false);
  const [MessageInfo, setIsMessageInfo] = useState(false);
  const [viewImage, setIviewImage] = useState(false);
  const [token, setToken] = useState("");
  const [ForgetToken, setForgetToken] = useState("");
  const [sideDraw, setSideDraw] = useState(false);
  const [LookAhedDraw, setLookAhedDraw] = useState(false);
  const [Employee, setEmployee] = useState({});
  const [Otp, setOtp] = useState();
  const [displaySize, setDisplaySize] = useState(window.innerWidth);
  const [hideMsgGroup, setHideMsgGroup] = useState(false);
  const [hideLookAhed, sethideLookAhed] = useState(false);
  const [DeleteEmpId, setDeleteEmpId] = useState();
  const [DeleteDocId, setDeleteDocId] = useState();
  const [NotificationCount, setNotificationCount] = useState(0);
  const [SelectedDate, setSelectDate] = useState();
  const [SelectedTime, setSelectTime] = useState();
  const [updateCount, setUpdateCount] = useState(0);
  useEffect(() => {
    const currentTime = new Date();
    // Mountain Time ke liye date aur time format karna
    const options = { timeZone: "America/Denver" };
    const formattedDate = new Intl.DateTimeFormat("en-US", {
      ...options,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).format(currentTime);

    const formattedTime = new Intl.DateTimeFormat("en-US", {
      ...options,
      hour: "numeric",
      minute: "2-digit",
      hour12: true,
    }).format(currentTime);

    setSelectDate(formattedDate);
    setSelectTime(formattedTime);
  }, []);

  const [GroupName, setGroupName] = useState("");
  const [ModalImageUrl, setModalImageUrl] = useState("");
  const [isMessageSeen, setIsMessageSeen] = useState([]);
  const [IsAttachments, setIsAttachments] = useState([]);
  const [msgSeenEmp, setMsgSeenEmp] = useState([]);
  const [loader, setLoader] = useState(false);
  const [OtpVal, setOtpVal] = useState("");
  const [ForgetEmail, setForgetEmail] = useState("");
  const [RealTimeData, setRealTimeData] = useState(0);

  useEffect(() => {
    const handleResize = () => {
      setDisplaySize(window.innerWidth);
    };
    setHideMsgGroup(displaySize > 1023 ? true : false);
    sethideLookAhed(displaySize > 1023 ? true : false);
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, [displaySize]);

  useEffect(() => {
    const checkAndSendNotifications = async (empData) => {
      const notificationsRef = collection(db, "scheduled");
      const messageRef = collection(db, "message");

      const querySnapshot = await getDocs(notificationsRef);
      const updates = [];

      const now = moment.tz("America/Denver");

      querySnapshot.forEach((doc) => {
        const data = doc.data();

        const notificationDate = moment.tz(
          `${data.date} ${data.time}`,
          "MM/DD/YYYY h:mm A",
          "America/Denver"
        );
        if (notificationDate.isSameOrBefore(now) && data.status === "pending") {
          updates.push(updateDoc(doc.ref, { status: "Sent" }));
          updates.push(
            addDoc(messageRef, {
              time: data?.time,
              message: data?.message,
              UserMsgSeen: [],
              images: data?.images,
              id: data.id,
              type: data?.type,
              createdAt: new Date(),
              employeeId: empData?.id,
            })
          );
        }
      });

      await Promise.all(updates);
    };

    const cookieData = Cookies.get("employe");
    if (cookieData) {
      const empData = JSON.parse(cookieData);
      const intervalId = setInterval(() => {
        checkAndSendNotifications(empData);
      }, 5000);

      return () => clearInterval(intervalId);
    }
  }, [updateCount]);

  return (
    <MyContext.Provider
      value={{
        setOtpVal,
        setRealTimeData,
        RealTimeData,
        OtpVal,
        PasswordSuccessFullChange,
        setPasswordSuccessFullChange,
        ChangePassword,
        setIsChangePassword,
        LogOut,
        setForgetToken,ForgetToken,
        setIsLogOut,
        setIsDropdown,
        IsDropdownOpen,
        isEditGroup,
        setEditGroup,
        LookScreen,
        setLookScreen,
        DeleteSchedule,
        setIsDeleteSchedule,
        setIsDeleteProfile,
        DeleteProfile,
        token,
        setToken,
        setIsViewAll,
        viewAll,
        AddMem,
        setIsAddMem,
        setIsMessageInfo,
        MessageInfo,
        viewImage,
        setIviewImage,
        hideMsgGroup,
        setHideMsgGroup,
        setSideDraw,
        sideDraw,
        hideLookAhed,
        LookAhedDraw,
        setLookAhedDraw,
        sethideLookAhed,
        setEmployee,
        Employee,
        setOtp,
        Otp,
        DeleteEmpId,
        setDeleteEmpId,
        DeleteDocId,
        setDeleteDocId,
        setSelectDate,
        SelectedDate,
        SelectedTime,
        setSelectTime,
        setNotificationCount,
        NotificationCount,
        setGroupName,
        GroupName,
        setModalImageUrl,
        ModalImageUrl,
        setIsMessageSeen,
        isMessageSeen,
        setIsAttachments,
        IsAttachments,
        setLoader,
        loader,
        setForgetEmail,
        ForgetEmail,
        msgSeenEmp,
        setMsgSeenEmp,
        updateCount,
        setUpdateCount,
      }}
    >
      {children}
    </MyContext.Provider>
  );
};
