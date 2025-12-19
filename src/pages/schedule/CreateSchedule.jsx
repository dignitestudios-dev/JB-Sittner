import React, { useContext, useState } from "react";
import { IoMdArrowBack } from "react-icons/io";
import { FaPlus } from "react-icons/fa6";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { ModernTimePicker } from "../../components/Picker/TimePicker";
import DatePicker from "../../components/Picker/DatePicker";
import {
  addDoc,
  collection,
  db,
  getDocs,
  getDownloadURL,
  query,
  ref,
  storage,
  uploadBytesResumable,
  where,
} from "../../firbase/FirebaseInit";
import { MyContext } from "../../context/GlobalContext";
import { toast } from "react-toastify";
import moment from "moment-timezone";
export default function CreateSchedule() {
  const navigate = useNavigate("");
  const { SelectedTime, SelectedDate, Employee, setLoader, loader } =
    useContext(MyContext);
  const locationState = useLocation();
  const [message, setMessage] = useState("");

  const generateUniqueId = async () => {
    const randomId = Math.floor(100000 + Math.random() * 900000).toString();
    const existingEmployee = await getDocs(
      query(collection(db, "scheduled"), where("id", "==", randomId))
    );
    if (!existingEmployee.empty) {
      return generateUniqueId();
    }
    return randomId;
  };

  const HandleScheduled = async (e) => {
    e.preventDefault();
    setLoader(true);

    const parsedDate = moment.tz(SelectedDate, "MM/DD/YYYY", "America/Denver");
    const currentDate = moment.tz("America/Denver");
    const futureDate = currentDate.clone().add(14, "days");
    // console.log(parsedDate.format(), futureDate.format(), "collectionname");
    if (
      parsedDate.isAfter(futureDate) &&
      locationState.state.collection.includes("look")
    ) {
      toast.error(
        "The selected date cannot be more than two weeks in the future."
      );
      setLoader(false);
      return;
    }

    const scheduledRef = collection(db, locationState.state.collection);
    const imageUrls = [];
    const docType = [];
    const loadingToastId = toast.loading("Uploading...");
    try {
      // console.log(SelectedDate, SelectedTime, "selectedDatess");
      const uniqueId = await generateUniqueId();
      for (const image of images) {
        const storageRef = ref(storage, `images/${uniqueId + image.name}`);
        await uploadBytesResumable(storageRef, image);
        const url = await getDownloadURL(storageRef);
        imageUrls.push({ url: url, name: image.name });
        docType.push(image.type);
      }
      await addDoc(scheduledRef, {
        date: SelectedDate,
        time: SelectedTime,
        message,
        id: uniqueId,
        images: imageUrls,
        status: "pending",
        createdAt: new Date(),
        type: docType,
        employeeId: Employee.id,
      });
      toast.update(loadingToastId, {
        render: "Scheduled successfully!",
        type: "success",
        isLoading: false,
        autoClose: 5000,
      });
      setLoader(false);
      locationState.state.collection == "look"
        ? navigate("/")
        : navigate("/schedule");
    } catch (error) {
      console.error("Failed to schedule:", error);
      toast.update(loadingToastId, {
        render: "Failed to schedule. Please try again.",
        type: "error",
        isLoading: false,
        autoClose: 5000,
      });
      setLoader(false);
    }
  };

  const [images, setImages] = useState([]);

  const handleImageChange = (e) => {
    const newImages = Array.from(e.target.files);
    setImages((prevImages) => [...prevImages, ...newImages]);
  };
  const handleRemoveImage = (index) => {
    setImages((prevImages) => prevImages.filter((_, i) => i !== index));
  };

  return (
    <div class="bg-[#F7F7F7] h-[90vh] py-5 px-5 ">
      <NavLink
        to={locationState.state.collection == "look" ? "/" : "/schedule"}
        className="font-semibold text-[24px] leading-[29px] flex items-center"
      >
        {" "}
        <IoMdArrowBack size={25} className="mr-2" /> Create Message
      </NavLink>

      <div class="bg-[#FFFFFF] mb-3 h-auto border rounded-[10px] border-[#E4E4E4] mt-6 px-3 lg:py-5 lg:px-10">
        <form onSubmit={HandleScheduled}>
          <div className="mt-5 grid grid-cols-1 gap-5 lg:grid-cols-2">
            <div className="mb-1 col-span-2">
              <textarea
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                className="bg-white border border-gray-300 text-gray-900 text-sm rounded-[12px] h-[127px] mt-1 block w-full p-2.5 focus:outline-[#0A8A33]"
                placeholder="Type Here...."
                required
              ></textarea>
            </div>
            <div className="mb-3 col-span-2">
              <label htmlFor="file">
                <div className="text-[#007AFF] flex items-center cursor-pointer">
                  <FaPlus className="mr-2" /> Attachment
                </div>
                <input
                  type="file"
                  className="hidden"
                  id="file"
                  multiple
                  onChange={handleImageChange}
                />
              </label>
              {images.length > 0 && (
                <div
                  className={`image-preview flex items-center flex-wrap mt-2 gap-2`}
                >
                  {images.map((image, targetIndex) => (
                    <div key={targetIndex} className="relative">
                      {image.type?.includes("image") ? (
                        <img
                          src={URL.createObjectURL(image)}
                          alt=""
                          className="h-[100px] rounded-md w-auto"
                        />
                      ) : image.type?.includes("video") ? (
                        <img
                          src="/video.webp"
                          alt=""
                          className="h-[100px] rounded-md w-[100px]"
                        />
                      ) : image.type?.includes("spreadsheetml") ? (
                        <img
                          src="/xl.webp"
                          alt=""
                          className="h-[100px] rounded-md w-[100px]"
                        />
                      ) : (
                        <img
                          src="/pdf.webp"
                          alt=""
                          className="h-[100px] rounded-md w-[100px]"
                        />
                      )}
                      <div
                        onClick={() => handleRemoveImage(targetIndex)}
                        className="absolute cursor-pointer top-0 right-0 bg-red-500 text-white rounded-full px-[6px] py-0"
                      >
                        X
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div className="mb-3 grid grid-cols-1 lg:grid-cols-2 col-span-1">
              <DatePicker />
              <ModernTimePicker />
            </div>
          </div>
          <div className="flex items-center gap-5 mt-5">
            <button
              type="submit"
              disabled={loader ? loader : false}
              className="text-white bg-[#0A8A33] rounded-lg w-[150px] h-[50px] px-5 py-2.5 text-center"
            >
              Schedule
            </button>
            <NavLink
              to={locationState.state.collection == "look" ? "/" : "/schedule"}
              className="bg-[#F1F1F1] font-bold rounded-lg w-[150px] h-[50px] px-5 py-2.5 text-center"
            >
              Cancel
            </NavLink>
          </div>
        </form>
        <div></div>
      </div>
    </div>
  );
}
